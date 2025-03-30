package server

import "fmt"

func (s *Server) sendWelcomeMail(email, handle string) error {
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
	s.mailLk.Lock()
	defer s.mailLk.Unlock()

	s.mail.To(email)
	s.mail.Subject("Password reset for " + s.config.Hostname)
	s.mail.Plain().Set(fmt.Sprintf("Hello %s. Your password reset code is %s.", handle, code))

	if err := s.mail.Send(); err != nil {
		return err
	}

	return nil
}

func (s *Server) sendEmailVerification(email, handle, code string) error {
	s.mailLk.Lock()
	defer s.mailLk.Unlock()

	s.mail.To(email)
	s.mail.Subject("Email verification for " + s.config.Hostname)
	s.mail.Plain().Set(fmt.Sprintf("Hello %s. Your email verification code is %s", handle, code))

	if err := s.mail.Send(); err != nil {
		return err
	}

	return nil
}
