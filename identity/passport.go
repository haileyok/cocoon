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
	h  *http.Client
	bc BackingCache
	mu sync.RWMutex
}

func NewPassport(h *http.Client, bc BackingCache) *Passport {
	if h == nil {
		h = http.DefaultClient
	}

	return &Passport{
		h:  h,
		bc: bc,
	}
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

	doc, err := FetchDidDoc(ctx, p.h, did)
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
