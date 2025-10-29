package server

import "fmt"

func (s *Server) sendWelcomeMail(email, handle string) error {
	if s.mail == nil {
		return nil
	}

	s.mailLk.Lock()
	defer s.mailLk.Unlock()

	s.mail.To(email)
	s.mail.Subject("Welcome to " + s.config.Hostname)
	s.mail.Plain().Set(fmt.Sprintf("Welcome to %s! Your handle is %s.", email, handle))

	if err := s.mail.Send(); err != nil {
		return err
	}

	return nil
}

func (s *Server) sendPasswordReset(email, handle, code string) error {
	if s.mail == nil {
		return nil
	}

	s.mailLk.Lock()
	defer s.mailLk.Unlock()

	s.mail.To(email)
	s.mail.Subject("Password reset for " + s.config.Hostname)
	s.mail.Plain().Set(fmt.Sprintf("Hello %s. Your password reset code is %s. This code will expire in ten minutes.", handle, code))

	if err := s.mail.Send(); err != nil {
		return err
	}

	return nil
}

func (s *Server) sendPlcTokenReset(email, handle, code string) error {
	if s.mail == nil {
		return nil
	}

	s.mailLk.Lock()
	defer s.mailLk.Unlock()

	s.mail.To(email)
	s.mail.Subject("PLC token for " + s.config.Hostname)
	s.mail.Plain().Set(fmt.Sprintf("Hello %s. Your PLC operation code is %s. This code will expire in ten minutes.", handle, code))

	if err := s.mail.Send(); err != nil {
		return err
	}

	return nil
}

func (s *Server) sendEmailUpdate(email, handle, code string) error {
	if s.mail == nil {
		return nil
	}

	s.mailLk.Lock()
	defer s.mailLk.Unlock()

	s.mail.To(email)
	s.mail.Subject("Email update for " + s.config.Hostname)
	s.mail.Plain().Set(fmt.Sprintf("Hello %s. Your email update code is %s. This code will expire in ten minutes.", handle, code))

	if err := s.mail.Send(); err != nil {
		return err
	}

	return nil
}

func (s *Server) sendEmailVerification(email, handle, code string) error {
	if s.mail == nil {
		return nil
	}

	s.mailLk.Lock()
	defer s.mailLk.Unlock()

	s.mail.To(email)
	s.mail.Subject("Email verification for " + s.config.Hostname)
	s.mail.Plain().Set(fmt.Sprintf("Hello %s. Your email verification code is %s. This code will expire in ten minutes.", handle, code))

	if err := s.mail.Send(); err != nil {
		return err
	}

	return nil
}
