package auth

import (
	"context"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

type Service struct {
	store     *Store
	passwords *Passwords
	email     *EmailDelivery
	webAuthn  *wa.WebAuthn
	webOrigin string
	oauth     *oauthConfig
}

func NewService(store *Store, passwords *Passwords) *Service {
	return &Service{store: store, passwords: passwords}
}

func (s *Service) Session(ctx context.Context, token, peer string, bootstrap bool) (*Session, error) {
	current, err := s.store.session(ctx, token)
	if err != nil || current != nil {
		return current, err
	}
	if !bootstrap {
		return nil, Unauthenticated
	}
	if err := s.store.throttle(ctx, "bootstrap/ip/"+peer, 60); err != nil {
		return nil, err
	}
	return s.store.anonymous(ctx)
}

func (s *Service) Register(ctx context.Context, peer, name, email, password string) error {
	name, err := Name(name)
	if err != nil {
		return err
	}
	email, err = Email(email)
	if err != nil {
		return err
	}
	if err = Password(password); err != nil {
		return err
	}
	if err = s.store.throttle(ctx, "register/ip/"+peer, 5); err != nil {
		return err
	}
	hash, err := s.passwords.Hash(ctx, password)
	if err != nil {
		return err
	}
	if err := s.store.register(ctx, name, email, hash); err != nil {
		return err
	}
	if s.email != nil {
		return s.RequestEmail(ctx, peer, email, "verification")
	}
	return nil
}

func (s *Service) Login(ctx context.Context, current *Session, peer, email, password string) (*Session, error) {
	email, err := Email(email)
	if err != nil {
		return nil, InvalidCredentials
	}
	if err = Password(password); err != nil {
		return nil, InvalidCredentials
	}
	if err = s.store.throttle(ctx, "login/ip/"+peer, 30); err != nil {
		return nil, err
	}
	if err = s.store.throttle(ctx, "login/email/"+email, 10); err != nil {
		return nil, err
	}
	a, err := s.store.account(ctx, email)
	if err != nil {
		return nil, err
	}
	hash := ""
	if a != nil {
		hash = a.Hash
	}
	match, err := s.passwords.Compare(ctx, password, hash)
	if err != nil {
		return nil, err
	}
	if !match || a == nil || a.ClosureAt != nil {
		return nil, InvalidCredentials
	}
	return s.store.rotate(ctx, current, a)
}

func (s *Service) Logout(ctx context.Context, current *Session) (*Session, error) {
	return s.store.rotate(ctx, current, nil)
}
