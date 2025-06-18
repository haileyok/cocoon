package provider

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/haileyok/cocoon/oauth/client_manager"
	"github.com/haileyok/cocoon/oauth/dpop/dpop_manager"
	"gorm.io/gorm"
)

type Provider struct {
	ClientManager *client_manager.ClientManager
	DpopManager   *dpop_manager.DpopManager

	hostname string
}

type Args struct {
	Hostname          string
	ClientManagerArgs client_manager.Args
	DpopManagerArgs   dpop_manager.Args
}

func NewProvider(args Args) *Provider {
	return &Provider{
		ClientManager: client_manager.New(args.ClientManagerArgs),
		DpopManager:   dpop_manager.New(args.DpopManagerArgs),
		hostname:      args.Hostname,
	}
}

func (p *Provider) NextNonce() string {
	return p.DpopManager.NextNonce()
}

type ParRequest struct {
	AuthenticateClientRequestBase
	ResponseType        string  `form:"response_type" json:"response_type" validate:"required"`
	CodeChallenge       *string `form:"code_challenge" json:"code_challenge" validate:"required"`
	CodeChallengeMethod string  `form:"code_challenge_method" json:"code_challenge_method" validate:"required"`
	State               string  `form:"state" json:"state" validate:"required"`
	RedirectURI         string  `form:"redirect_uri" json:"redirect_uri" validate:"required"`
	Scope               string  `form:"scope" json:"scope" validate:"required"`
	LoginHint           *string `form:"login_hint" json:"login_hint,omitempty"`
	DpopJkt             *string `form:"dpop_jkt" json:"dpop_jkt,omitempty"`
}

func (opr *ParRequest) Scan(value any) error {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to unmarshal OauthParRequest value")
	}
	return json.Unmarshal(b, opr)
}

func (opr ParRequest) Value() (driver.Value, error) {
	return json.Marshal(opr)
}

type OauthToken struct {
	gorm.Model
	ClientId     string     `gorm:"index"`
	ClientAuth   ClientAuth `gorm:"type:json"`
	Parameters   ParRequest `gorm:"type:json"`
	ExpiresAt    time.Time  `gorm:"index"`
	DeviceId     string
	Sub          string `gorm:"index"`
	Code         string `gorm:"index"`
	Token        string `gorm:"uniqueIndex"`
	RefreshToken string `gorm:"uniqueIndex"`
}

type OauthAuthorizationRequest struct {
	gorm.Model
	RequestId  string     `gorm:"primaryKey"`
	ClientId   string     `gorm:"index"`
	ClientAuth ClientAuth `gorm:"type:json"`
	Parameters ParRequest `gorm:"type:json"`
	ExpiresAt  time.Time  `gorm:"index"`
	DeviceId   *string
	Sub        *string
	Code       *string
	Accepted   *bool
}
