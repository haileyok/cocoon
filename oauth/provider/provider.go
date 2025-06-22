package provider

import (
	"github.com/haileyok/cocoon/oauth/client"
	"github.com/haileyok/cocoon/oauth/dpop"
)

type Provider struct {
	ClientManager *client.Manager
	DpopManager   *dpop.Manager

	hostname string
}

type Args struct {
	Hostname          string
	ClientManagerArgs client.ManagerArgs
	DpopManagerArgs   dpop.ManagerArgs
}

func NewProvider(args Args) *Provider {
	return &Provider{
		ClientManager: client.NewManager(args.ClientManagerArgs),
		DpopManager:   dpop.NewManager(args.DpopManagerArgs),
		hostname:      args.Hostname,
	}
}

func (p *Provider) NextNonce() string {
	return p.DpopManager.NextNonce()
}
