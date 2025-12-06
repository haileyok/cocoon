package server

import (
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ServerReserveSigningKeyRequest struct {
	Did *string `json:"did"`
}

type ServerReserveSigningKeyResponse struct {
	SigningKey string `json:"signingKey"`
}

func (s *Server) handleServerReserveSigningKey(e echo.Context) error {
	var req ServerReserveSigningKeyRequest
	if err := e.Bind(&req); err != nil {
		s.logger.Error("could not bind reserve signing key request", "error", err)
		return helpers.ServerError(e, nil)
	}

	if req.Did != nil && *req.Did != "" {
		var existing models.ReservedKey
		if err := s.db.Raw("SELECT * FROM reserved_keys WHERE did = ?", nil, *req.Did).Scan(&existing).Error; err == nil && existing.KeyDid != "" {
			return e.JSON(200, ServerReserveSigningKeyResponse{
				SigningKey: existing.KeyDid,
			})
		}
	}

	k, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		s.logger.Error("error creating signing key", "endpoint", "com.atproto.server.reserveSigningKey", "error", err)
		return helpers.ServerError(e, nil)
	}

	pubKey, err := k.PublicKey()
	if err != nil {
		s.logger.Error("error getting public key", "endpoint", "com.atproto.server.reserveSigningKey", "error", err)
		return helpers.ServerError(e, nil)
	}

	keyDid := pubKey.DIDKey()

	reservedKey := models.ReservedKey{
		KeyDid:     keyDid,
		Did:        req.Did,
		PrivateKey: k.Bytes(),
		CreatedAt:  time.Now(),
	}

	if err := s.db.Create(&reservedKey, nil).Error; err != nil {
		s.logger.Error("error storing reserved key", "endpoint", "com.atproto.server.reserveSigningKey", "error", err)
		return helpers.ServerError(e, nil)
	}

	s.logger.Info("reserved signing key", "keyDid", keyDid, "forDid", req.Did)

	return e.JSON(200, ServerReserveSigningKeyResponse{
		SigningKey: keyDid,
	})
}

func (s *Server) getReservedKey(keyDidOrDid string) (*models.ReservedKey, error) {
	var reservedKey models.ReservedKey

	if err := s.db.Raw("SELECT * FROM reserved_keys WHERE key_did = ?", nil, keyDidOrDid).Scan(&reservedKey).Error; err == nil && reservedKey.KeyDid != "" {
		return &reservedKey, nil
	}

	if err := s.db.Raw("SELECT * FROM reserved_keys WHERE did = ?", nil, keyDidOrDid).Scan(&reservedKey).Error; err == nil && reservedKey.KeyDid != "" {
		return &reservedKey, nil
	}

	return nil, nil
}

func (s *Server) deleteReservedKey(keyDid string, did *string) error {
	if err := s.db.Exec("DELETE FROM reserved_keys WHERE key_did = ?", nil, keyDid).Error; err != nil {
		return err
	}

	if did != nil && *did != "" {
		if err := s.db.Exec("DELETE FROM reserved_keys WHERE did = ?", nil, *did).Error; err != nil {
			return err
		}
	}

	return nil
}
