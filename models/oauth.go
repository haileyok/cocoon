package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

type OauthParRequest struct {
	ResponseType        string  `form:"response_type" json:"response_type" validate:"required"`
	CodeChallenge       string  `form:"code_challenge" json:"code_challenge" validate:"required"`
	CodeChallengeMethod string  `form:"code_challenge_method" json:"code_challenge_method" validate:"required"`
	ClientID            string  `form:"client_id" json:"client_id" validate:"required"`
	State               string  `form:"state" json:"state" validate:"required"`
	RedirectURI         string  `form:"redirect_uri" json:"redirect_uri" validate:"required"`
	Scope               string  `form:"scope" json:"scope" validate:"required"`
	ClientAssertionType *string `form:"client_assertion_type" json:"client_assertion_type,omitempty"`
	ClientAssertion     *string `form:"client_assertion" json:"client_assertion,omitempty"`
	LoginHint           *string `form:"login_hint" json:"login_hint,omitempty"`
	DpopJkt             *string `form:"dpop_jkt" json:"dpop_jkt,omitempty"`
}

func (opr *OauthParRequest) Scan(value any) error {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to unmarshal OauthParRequest value")
	}
	return json.Unmarshal(b, opr)
}

func (opr OauthParRequest) Value() (driver.Value, error) {
	return json.Marshal(opr)
}

type OauthClientAuth struct {
	Method string
	Alg    string
	Kid    string
	Jkt    string
	Jti    string
	Exp    *float64
}

func (oca *OauthClientAuth) Scan(value any) error {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to unmarshal OauthClientAuth value")
	}
	return json.Unmarshal(b, oca)
}

func (oca OauthClientAuth) Value() (driver.Value, error) {
	return json.Marshal(oca)
}

type OauthAuthorizationRequest struct {
	RequestId  string          `gorm:"primaryKey"`
	ClientId   string          `gorm:"index"`
	ClientAuth OauthClientAuth `gorm:"type:json"`
	Parameters OauthParRequest `gorm:"type:json"`
	ExpiresAt  time.Time       `gorm:"index"`
	DeviceId   *string
	Sub        *string
	Code       *string
	Accepted   *bool
}
