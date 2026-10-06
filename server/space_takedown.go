package server

import (
	"context"
)

// isTakenDown reports whether an account is taken down.
func (s *Server) isTakenDown(did string) (bool, error) {
	var rows []struct{ TakedownRef *string }
	if err := s.db.Raw(context.Background(), "SELECT takedown_ref FROM repos WHERE did = ?", nil, did).Scan(&rows).Error; err != nil {
		return false, err
	}
	return len(rows) > 0 && rows[0].TakedownRef != nil, nil
}

// assertNotTakenDown refuses a taken-down account's space requests.
func (s *Server) assertNotTakenDown(did string) error {
	down, err := s.isTakenDown(did)
	if err != nil {
		return err
	}
	if down {
		return errAuthRequired("AccountTakedown", "Account has been taken down")
	}
	return nil
}
