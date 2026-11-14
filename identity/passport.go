package identity

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bluesky-social/gttp"
	"github.com/haileyok/cocoon/internal/helpers"
)

type BackingCache interface {
	GetDoc(did string) (*DidDoc, bool)
	PutDoc(did string, doc *DidDoc) error
	BustDoc(did string) error

	GetDid(handle string) (string, bool)
	PutDid(handle string, did string) error
	BustDid(handle string) error
}

type Passport struct {
	h        *http.Client
	plcHTTP  *http.Client
	bc       BackingCache
	plcURL   string
	resolver TXTResolver
	mu       sync.RWMutex
}

// PassportOption configures optional Passport behavior.
type PassportOption func(*Passport)

// WithPlcURL sets the PLC directory used to resolve did:plc documents.
// An empty value keeps DefaultPlcURL.
func WithPlcURL(plcURL string) PassportOption {
	return func(p *Passport) {
		if plcURL != "" {
			p.plcURL = plcURL
		}
	}
}

// WithTXTResolver overrides the DNS resolver used for _atproto TXT lookups.
// Tests use it to keep handle resolution off live DNS; an operator could use it
// to pin handle resolution to a specific resolver.
func WithTXTResolver(resolver TXTResolver) PassportOption {
	return func(p *Passport) {
		if resolver != nil {
			p.resolver = resolver
		}
	}
}

// NewPassport uses restricted web fetching and a separate client for the
// configured PLC directory. An explicit client overrides both defaults.
func NewPassport(h *http.Client, bc BackingCache, opts ...PassportOption) *Passport {
	plcHTTP := h
	if h == nil {
		h = helpers.NewSafeFetchClient()
		plcHTTP = gttp.New(
			gttp.WithNoRedirects(),
			gttp.WithNoProxy(),
			gttp.WithMaxResponseBodyBytes(helpers.SafeFetchClientMaxBodyBytes),
			gttp.WithTimeout(10*time.Second),
			gttp.WithNoRetries(),
		)
	}

	p := &Passport{
		h:        h,
		plcHTTP:  plcHTTP,
		bc:       bc,
		plcURL:   DefaultPlcURL,
		resolver: net.DefaultResolver,
	}
	for _, opt := range opts {
		opt(p)
	}

	return p
}

func (p *Passport) FetchDoc(ctx context.Context, did string) (*DidDoc, error) {
	skipCache, _ := ctx.Value("skip-cache").(bool)

	if !skipCache {
		p.mu.RLock()
		cached, ok := p.bc.GetDoc(did)
		p.mu.RUnlock()

		if ok {
			return cached, nil
		}
	}

	h := p.h
	if strings.HasPrefix(did, "did:plc:") {
		h = p.plcHTTP
	}
	doc, err := FetchDidDoc(ctx, h, p.plcURL, did)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.bc.PutDoc(did, doc)
	p.mu.Unlock()

	return doc, nil
}

func (p *Passport) ResolveHandle(ctx context.Context, handle string) (string, error) {
	skipCache, _ := ctx.Value("skip-cache").(bool)

	if !skipCache {
		p.mu.RLock()
		cached, ok := p.bc.GetDid(handle)
		p.mu.RUnlock()

		if ok {
			return cached, nil
		}
	}

	did, err := resolveHandle(ctx, p.resolver, p.h, handle)
	if err != nil {
		return "", err
	}

	p.mu.Lock()
	p.bc.PutDid(handle, did)
	p.mu.Unlock()

	return did, nil
}

func (p *Passport) BustDoc(ctx context.Context, did string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bc.BustDoc(did)
}

func (p *Passport) BustDid(ctx context.Context, handle string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bc.BustDid(handle)
}
