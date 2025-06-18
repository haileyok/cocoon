package constants

import "time"

const (
	MaxDpopAge         = 10 * time.Second
	DpopCheckTolerance = 5 * time.Second

	NonceSecretByteLength = 32

	NonceMaxRotationInterval = DpopNonceMaxAge / 3
	NonceMinRotationInterval = 1 * time.Second

	JTICacheSize = 100_000
	JTITtl       = 24 * time.Hour

	ClientAssertionTypeJwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	ParExpiresIn                 = 5 * time.Minute

	ClientAssertionMaxAge = 1 * time.Minute

	DeviceIdPrefix      = "dev-"
	DeviceIdBytesLength = 16

	SessionIdPrefix      = "ses-"
	SessionIdBytesLength = 16

	RefreshTokenPrefix      = "ref-"
	RefreshTokenBytesLength = 32

	RequestIdPrefix      = "req-"
	RequestIdBytesLength = 16
	RequestUriPrefix     = "urn:ietf:params:oauth:request_uri:"

	CodePrefix      = "cod-"
	CodeBytesLength = 32

	TokenIdPrefix      = "tok-"
	TokenIdBytesLength = 16

	TokenMaxAge = 60 * time.Minute

	AuthorizationInactivityTimeout = 5 * time.Minute

	DpopNonceMaxAge = 3 * time.Minute

	ConfidentialClientSessionLifetime = 2 * 365 * 24 * time.Hour // 2 years
	ConfidentialClientRefreshLifetime = 3 * 30 * 24 * time.Hour  // 3 months

	PublicClientSessionLifetime = 2 * 7 * 24 * time.Hour // 2 weeks
	PublicClientRefreshLifetime = PublicClientSessionLifetime
)
