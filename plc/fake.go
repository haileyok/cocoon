package plc

import (
	"context"
	"fmt"
	"sync"
)

// FakePLC is a PLCClient that generates valid DIDs locally without contacting
// a real PLC directory. Useful for tests where you want account creation and
// CRUD to work without any external dependencies.
//
// It embeds *Client to reuse the real signing and credential logic, and only
// overrides SendOperation to skip the network POST.
type FakePLC struct {
	*Client

	mu         sync.Mutex
	operations map[string]*Operation // did -> latest operation
}

// FakePLCArgs configures a FakePLC instance.
type FakePLCArgs struct {
	RotationKey []byte
	PdsHostname string
}

// NewFakePLC creates a FakePLC backed by the given rotation key.
func NewFakePLC(args *FakePLCArgs) (*FakePLC, error) {
	c, err := NewClient(&ClientArgs{
		RotationKey: args.RotationKey,
		PdsHostname: args.PdsHostname,
	})
	if err != nil {
		return nil, fmt.Errorf("fake plc: %w", err)
	}

	return &FakePLC{
		Client:     c,
		operations: make(map[string]*Operation),
	}, nil
}

// SendOperation records the operation in memory instead of POSTing it to a
// real PLC directory.
func (f *FakePLC) SendOperation(_ context.Context, did string, op *Operation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.operations[did] = op
	return nil
}

// GetOperation returns the latest operation stored for a DID, or nil if none.
func (f *FakePLC) GetOperation(did string) *Operation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.operations[did]
}
