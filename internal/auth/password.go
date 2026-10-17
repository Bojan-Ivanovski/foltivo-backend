package auth

import (
	"context"
	"github.com/alexedwards/argon2id"
)

type Passwords struct {
	params *argon2id.Params
	slots  chan struct{}
	dummy  string
}

// NewPasswords uses RFC 9106's 64 MiB profile and admits at most two memory-heavy
// operations at once. The channel is shared by all requests in this process.
func NewPasswords() (*Passwords, error) {
	return newPasswords(&argon2id.Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 4, SaltLength: 16, KeyLength: 32})
}

func newPasswords(params *argon2id.Params) (*Passwords, error) {
	dummy, err := argon2id.CreateHash("unknown account dummy password", params)
	if err != nil {
		return nil, Unavailable
	}
	return &Passwords{params: params, slots: make(chan struct{}, 2), dummy: dummy}, nil
}

func (p *Passwords) acquire(ctx context.Context) error {
	select {
	case p.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return Unavailable
	default:
		return &Error{Status: 503, Code: "busy", Message: "Authentication is busy. Try again shortly.", RetryAfter: 2}
	}
}

func (p *Passwords) Hash(ctx context.Context, password string) (string, error) {
	if err := p.acquire(ctx); err != nil {
		return "", err
	}
	defer func() { <-p.slots }()
	hash, err := argon2id.CreateHash(password, p.params)
	return hash, safe(err)
}

func (p *Passwords) Compare(ctx context.Context, password, hash string) (bool, error) {
	if err := p.acquire(ctx); err != nil {
		return false, err
	}
	defer func() { <-p.slots }()
	if hash == "" {
		hash = p.dummy
	}
	match, err := argon2id.ComparePasswordAndHash(password, hash)
	return match, safe(err)
}
