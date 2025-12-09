package dpop

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"sync"
	"time"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth/constants"
)

type Nonce struct {
	rotationInterval time.Duration
	secret           []byte

	mu sync.RWMutex

	counter int64
	prev    string
	curr    string
	next    string
}

type NonceArgs struct {
	RotationInterval time.Duration
	Secret           []byte
	OnSecretCreated  func([]byte)
}

func NewNonce(args NonceArgs) *Nonce {
	if args.RotationInterval == 0 {
		args.RotationInterval = constants.NonceMaxRotationInterval / 3
	}

	if args.RotationInterval > constants.NonceMaxRotationInterval {
		args.RotationInterval = constants.NonceMaxRotationInterval
	}

	if args.Secret == nil {
		args.Secret = helpers.RandomBytes(constants.NonceSecretByteLength)
		args.OnSecretCreated(args.Secret)
	}

	n := &Nonce{
		rotationInterval: args.RotationInterval,
		secret:           args.Secret,
		mu:               sync.RWMutex{},
	}

	n.counter = n.currentCounter()
	n.prev = n.compute(n.counter - 1)
	n.curr = n.compute(n.counter)
	n.next = n.compute(n.counter + 1)

	return n
}

func (n *Nonce) currentCounter() int64 {
	return time.Now().UnixNano() / int64(n.rotationInterval)
}

func (n *Nonce) compute(counter int64) string {
	h := hmac.New(sha256.New, n.secret)
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, uint64(counter))
	h.Write(counterBytes)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (n *Nonce) rotate() {
	counter := n.currentCounter()
	diff := counter - n.counter

	switch diff {
	case 0:
	// counter == n.counter, do nothing
	case 1:
		n.prev = n.curr
		n.curr = n.next
		n.next = n.compute(counter + 1)
	case 2:
		n.prev = n.next
		n.curr = n.compute(counter)
		n.next = n.compute(counter + 1)
	default:
		n.prev = n.compute(counter - 1)
		n.curr = n.compute(counter)
		n.next = n.compute(counter + 1)
	}

	n.counter = counter
}

func (n *Nonce) NextNonce() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.rotate()
	return n.next
}

func (n *Nonce) Check(nonce string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.rotate()
	return nonce == n.prev || nonce == n.curr || nonce == n.next
}
