package server

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/gorilla/sessions"
	"github.com/haileyok/cocoon/models"
	"gorm.io/gorm"
)

const (
	sessionDidKey  = "did"
	sessionDidsKey = "dids"
)

func normalizeSessionDids(dids []string) []string {
	normalized := make([]string, 0, len(dids))
	for _, did := range dids {
		if did == "" || slices.Contains(normalized, did) {
			continue
		}
		normalized = append(normalized, did)
	}
	return normalized
}

func getSessionDids(sess *sessions.Session) []string {
	if sess == nil {
		return nil
	}

	if val, ok := sess.Values[sessionDidsKey]; ok {
		switch dids := val.(type) {
		case []string:
			return normalizeSessionDids(dids)
		case []any:
			out := make([]string, 0, len(dids))
			for _, did := range dids {
				if s, ok := did.(string); ok {
					out = append(out, s)
				}
			}
			return normalizeSessionDids(out)
		}
	}

	if did, ok := sess.Values[sessionDidKey].(string); ok && did != "" {
		return []string{did}
	}

	return nil
}

func setSessionDids(sess *sessions.Session, dids []string) {
	if sess == nil {
		return
	}

	normalized := normalizeSessionDids(dids)
	if len(normalized) == 0 {
		delete(sess.Values, sessionDidKey)
		delete(sess.Values, sessionDidsKey)
		return
	}

	sess.Values[sessionDidsKey] = normalized
	if activeDid, ok := sess.Values[sessionDidKey].(string); !ok || !slices.Contains(normalized, activeDid) {
		sess.Values[sessionDidKey] = normalized[0]
	}
}

func getActiveSessionDid(sess *sessions.Session) string {
	if sess == nil {
		return ""
	}

	dids := getSessionDids(sess)
	if len(dids) == 0 {
		return ""
	}

	if activeDid, ok := sess.Values[sessionDidKey].(string); ok && slices.Contains(dids, activeDid) {
		return activeDid
	}
	return dids[0]
}

func setActiveSessionDid(sess *sessions.Session, did string) bool {
	if sess == nil || did == "" {
		return false
	}

	dids := getSessionDids(sess)
	if !slices.Contains(dids, did) {
		dids = append(dids, did)
	}
	setSessionDids(sess, dids)

	current, _ := sess.Values[sessionDidKey].(string)
	if current == did {
		return false
	}
	sess.Values[sessionDidKey] = did
	return true
}

func removeSessionDid(sess *sessions.Session, did string) {
	if sess == nil || did == "" {
		return
	}

	next := make([]string, 0)
	for _, existingDid := range getSessionDids(sess) {
		if existingDid != did {
			next = append(next, existingDid)
		}
	}
	setSessionDids(sess, next)
}

func (s *Server) getSessionAccountActors(ctx context.Context, sess *sessions.Session) ([]models.RepoActor, bool, error) {
	changed := false
	validDids := make([]string, 0)
	var accounts []models.RepoActor
	for _, did := range getSessionDids(sess) {
		repo, err := s.getRepoActorByDid(ctx, did)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				changed = true
				continue
			}
			return nil, changed, err
		}
		validDids = append(validDids, did)
		accounts = append(accounts, *repo)
	}

	if changed {
		setSessionDids(sess, validDids)
	}
	return accounts, changed, nil
}

func (s *Server) resolveLoginHintToDid(ctx context.Context, loginHint string) (string, error) {
	loginHint = strings.TrimSpace(loginHint)
	if loginHint == "" {
		return "", gorm.ErrRecordNotFound
	}

	if _, err := syntax.ParseDID(loginHint); err == nil {
		return loginHint, nil
	}

	normalizedHandle := strings.ToLower(loginHint)
	if _, err := syntax.ParseHandle(normalizedHandle); err == nil {
		actor, err := s.getActorByHandle(ctx, normalizedHandle)
		if err != nil {
			return "", err
		}
		return actor.Did, nil
	}

	return "", gorm.ErrRecordNotFound
}
