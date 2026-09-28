package server

import (
	"context"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/constants"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/hako/durafmt"
)

const (
	// clientLookupTimeout bounds how long the account page waits on client
	// metadata. Apps that don't answer in time are shown by their hostname.
	clientLookupTimeout = 2 * time.Second

	clientDisplayTTL       = 30 * time.Minute
	clientDisplayFailedTTL = 2 * time.Minute

	// maxOauthSessionLifetime and maxOauthRefreshLifetime are the longest
	// lifetimes any client gets. Tokens older than these can never be used.
	maxOauthSessionLifetime = constants.ConfidentialClientSessionLifetime
	maxOauthRefreshLifetime = constants.ConfidentialClientRefreshLifetime

	oauthTokenCleanupInterval = time.Hour
)

// accountSession is one signed-in OAuth session shown on the account page.
type accountSession struct {
	ID            uint
	IP            string
	Confidential  bool
	CreatedAt     time.Time
	LastActive    time.Time
	SignedInAgo   string
	LastActiveAgo string
	ExpiresIn     string
}

// accountApp groups the sessions a single OAuth client holds.
type accountApp struct {
	ClientID      string
	Name          string
	Host          string
	URI           string
	Initial       string
	Sessions      []accountSession
	LastActive    time.Time
	LastActiveAgo string
}

type clientDisplay struct {
	Name string
	URI  string
}

// oauthSessionDeadline is when a token stops being refreshable: the earlier
// of the absolute session lifetime and the sliding refresh window.
func oauthSessionDeadline(t provider.OauthToken) time.Time {
	sessionLifetime := constants.PublicClientSessionLifetime
	refreshLifetime := constants.PublicClientRefreshLifetime
	if t.ClientAuth.Method != "none" {
		sessionLifetime = constants.ConfidentialClientSessionLifetime
		refreshLifetime = constants.ConfidentialClientRefreshLifetime
	}
	deadline := t.CreatedAt.Add(sessionLifetime)
	if refresh := t.UpdatedAt.Add(refreshLifetime); refresh.Before(deadline) {
		deadline = refresh
	}
	return deadline
}

// liveOauthTokens returns the account's OAuth tokens that can still be
// refreshed. The query only reads rows that could possibly be live, so the
// cost tracks active sessions rather than every session ever issued.
func (s *Server) liveOauthTokens(ctx context.Context, did string, sessionVersion int64, now time.Time) ([]provider.OauthToken, error) {
	var tokens []provider.OauthToken
	if err := s.db.Raw(ctx,
		"SELECT * FROM oauth_tokens WHERE sub = ? AND session_version = ? AND created_at > ? AND updated_at > ? ORDER BY updated_at DESC",
		nil, did, sessionVersion, now.Add(-maxOauthSessionLifetime), now.Add(-maxOauthRefreshLifetime),
	).Scan(&tokens).Error; err != nil {
		return nil, err
	}

	live := tokens[:0]
	for _, t := range tokens {
		if now.Before(oauthSessionDeadline(t)) {
			live = append(live, t)
		}
	}
	return live, nil
}

func clientHost(clientID string) string {
	u, err := url.Parse(clientID)
	if err != nil || u.Host == "" {
		return clientID
	}
	return u.Hostname()
}

func (s *Server) clientDisplayCache() cache.Cache[string, clientDisplay] {
	s.clientDisplayOnce.Do(func() {
		s.clientDisplays = cache.NewCache[string, clientDisplay]().WithLRU().WithMaxKeys(1000)
	})
	return s.clientDisplays
}

// describeClients resolves display details for each client ID at most once,
// in parallel, and never waits longer than clientLookupTimeout overall.
func (s *Server) describeClients(ctx context.Context, clientIDs []string) map[string]clientDisplay {
	out := make(map[string]clientDisplay, len(clientIDs))
	c := s.clientDisplayCache()

	var missing []string
	for _, id := range clientIDs {
		if d, ok := c.Get(id); ok {
			out[id] = d
		} else {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 || s.oauthProvider == nil {
		for _, id := range missing {
			out[id] = clientDisplay{}
		}
		return out
	}

	ctx, cancel := context.WithTimeout(ctx, clientLookupTimeout)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, id := range missing {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			d := clientDisplay{}
			ttl := clientDisplayFailedTTL
			if md, err := s.oauthProvider.ClientManager.GetMetadata(ctx, id); err == nil {
				d = clientDisplay{Name: strings.TrimSpace(md.ClientName), URI: md.ClientURI}
				ttl = clientDisplayTTL
			}
			c.Set(id, d, ttl)
			mu.Lock()
			out[id] = d
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	return out
}

func shortDuration(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	return durafmt.Parse(d).LimitFirstN(1).String()
}

// safeClientURI only links to web pages, so a client can't smuggle a
// javascript: URL onto the account page.
func safeClientURI(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	return u.String()
}

// loadAccountApps returns the account's live OAuth sessions grouped by app,
// most recently used first.
func (s *Server) loadAccountApps(ctx context.Context, repo *models.RepoActor, now time.Time) ([]accountApp, error) {
	tokens, err := s.liveOauthTokens(ctx, repo.Repo.Did, repo.SessionVersion, now)
	if err != nil {
		return nil, err
	}

	byClient := map[string]*accountApp{}
	var order []string
	for _, t := range tokens {
		app, ok := byClient[t.ClientId]
		if !ok {
			app = &accountApp{ClientID: t.ClientId, Host: clientHost(t.ClientId)}
			byClient[t.ClientId] = app
			order = append(order, t.ClientId)
		}
		app.Sessions = append(app.Sessions, accountSession{
			ID:            t.ID,
			IP:            t.Ip,
			Confidential:  t.ClientAuth.Method != "none",
			CreatedAt:     t.CreatedAt,
			LastActive:    t.UpdatedAt,
			SignedInAgo:   shortDuration(now.Sub(t.CreatedAt)),
			LastActiveAgo: shortDuration(now.Sub(t.UpdatedAt)),
			ExpiresIn:     durafmt.Parse(oauthSessionDeadline(t).Sub(now)).LimitFirstN(1).String(),
		})
		if t.UpdatedAt.After(app.LastActive) {
			app.LastActive = t.UpdatedAt
		}
	}

	displays := s.describeClients(ctx, order)
	apps := make([]accountApp, 0, len(order))
	for _, id := range order {
		app := byClient[id]
		d := displays[id]
		app.Name = d.Name
		if app.Name == "" {
			app.Name = app.Host
		}
		app.URI = safeClientURI(d.URI)
		for _, r := range app.Name {
			app.Initial = strings.ToUpper(string(r))
			break
		}
		app.LastActiveAgo = shortDuration(now.Sub(app.LastActive))
		apps = append(apps, *app)
	}
	sort.SliceStable(apps, func(i, j int) bool { return apps[i].LastActive.After(apps[j].LastActive) })
	return apps, nil
}

// pruneOauthTokens deletes OAuth tokens that can never be used again:
// past every lifetime, or issued before the account's current session
// version (a password reset or "sign out everywhere").
func (s *Server) pruneOauthTokens(ctx context.Context, now time.Time) (int64, error) {
	res := s.db.Exec(ctx,
		"DELETE FROM oauth_tokens WHERE created_at < ? OR updated_at < ?",
		nil, now.Add(-maxOauthSessionLifetime), now.Add(-maxOauthRefreshLifetime),
	)
	if res.Error != nil {
		return 0, res.Error
	}
	n := res.RowsAffected

	res = s.db.Exec(ctx,
		"DELETE FROM oauth_tokens WHERE session_version < (SELECT r.session_version FROM repos r WHERE r.did = oauth_tokens.sub)",
		nil,
	)
	if res.Error != nil {
		return n, res.Error
	}
	return n + res.RowsAffected, nil
}

func (s *Server) oauthTokenCleanupRoutine(ctx context.Context) {
	run := func() {
		n, err := s.pruneOauthTokens(ctx, time.Now())
		if err != nil {
			s.logger.Error("pruning expired oauth tokens", "error", err)
			return
		}
		if n > 0 {
			s.logger.Info("pruned expired oauth tokens", "count", n)
		}
	}

	run()
	ticker := time.NewTicker(oauthTokenCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
