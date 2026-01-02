package dpop

import (
	"sync"
	"time"

	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/haileyok/cocoon/oauth/constants"
)

type jtiCache struct {
	mu    sync.Mutex
	cache cache.Cache[string, bool]
}

func newJTICache(size int) *jtiCache {
	cache := cache.NewCache[string, bool]().WithTTL(24 * time.Hour).WithLRU().WithTTL(constants.JTITtl).WithMaxKeys(size)
	return &jtiCache{
		cache: cache,
		mu:    sync.Mutex{},
	}
}

func (c *jtiCache) add(jti string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cache.Add(jti, true)
}
