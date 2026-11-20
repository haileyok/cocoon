package provider

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

type ClientAuth struct {
	Method string
	Alg    string
	Kid    string
	Jkt    string
	Jti    string
	Exp    *float64
}

func (ca *ClientAuth) Scan(value any) error {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to unmarshal OauthParRequest value")
	}
	return json.Unmarshal(b, ca)
}

func (ca ClientAuth) Value() (driver.Value, error) {
	return json.Marshal(ca)
}

type ParRequest struct {
	AuthenticateClientRequestBase
	ResponseType        string  `form:"response_type" json:"response_type" query:"response_type" validate:"required"`
	CodeChallenge       *string `form:"code_challenge" json:"code_challenge" query:"code_challenge" validate:"required"`
	CodeChallengeMethod string  `form:"code_challenge_method" json:"code_challenge_method" query:"code_challenge_method" validate:"required"`
	State               string  `form:"state" json:"state" query:"state" validate:"required"`
	RedirectURI         string  `form:"redirect_uri" json:"redirect_uri" query:"redirect_uri" validate:"required"`
	Scope               string  `form:"scope" json:"scope" query:"scope" validate:"required"`
	LoginHint           *string `form:"login_hint" query:"login_hint" json:"login_hint,omitempty"`
	DpopJkt             *string `form:"dpop_jkt" query:"dpop_jkt" json:"dpop_jkt,omitempty"`
	ResponseMode        *string `form:"response_mode" json:"response_mode,omitempty" query:"response_mode"`
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
	ClientId       string     `gorm:"index"`
	ClientAuth     ClientAuth `gorm:"type:json"`
	Parameters     ParRequest `gorm:"type:json"`
	ExpiresAt      time.Time  `gorm:"index"`
	DeviceId       string
	Sub            string `gorm:"index"`
	SessionVersion int64  `gorm:"not null;default:0"`
	Code           string `gorm:"index"`
	Token          string `gorm:"uniqueIndex"`
	RefreshToken   string `gorm:"uniqueIndex"`
	Ip             string
}

// OauthUsedRefreshToken records a rotated refresh token, so a later replay
// can find and revoke its session. Only a SHA-256 digest is stored. Rows
// whose session no longer exists are pruned with expired OAuth tokens.
type OauthUsedRefreshToken struct {
	TokenHash    string `gorm:"primaryKey"`
	OauthTokenID uint   `gorm:"not null"`
}

type OauthAuthorizationRequest struct {
	gorm.Model
	RequestId      string     `gorm:"primaryKey"`
	ClientId       string     `gorm:"index"`
	ClientAuth     ClientAuth `gorm:"type:json"`
	Parameters     ParRequest `gorm:"type:json"`
	ExpiresAt      time.Time  `gorm:"index"`
	DeviceId       *string
	Sub            *string
	SessionVersion int64 `gorm:"not null;default:0"`
	Code           *string
	Accepted       *bool
	Ip             string
}
