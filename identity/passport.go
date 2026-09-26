package identity

import (
	"context"
	"net/http"
	"sync"
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
	h      *http.Client
	bc     BackingCache
	plcURL string
	mu     sync.RWMutex
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

func NewPassport(h *http.Client, bc BackingCache, opts ...PassportOption) *Passport {
	if h == nil {
		h = http.DefaultClient
	}

	p := &Passport{
		h:      h,
		bc:     bc,
		plcURL: DefaultPlcURL,
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

	doc, err := FetchDidDoc(ctx, p.h, p.plcURL, did)
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

	did, err := ResolveHandle(ctx, p.h, handle)
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
