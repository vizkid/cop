package local

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
)

var errSigningIdentity = errors.New("resolved signing key is invalid or does not match the expected public key")

func signingPublic(text string) (ssh.PublicKey, error) {
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(text))
	if err != nil || len(options) != 0 || len(rest) != 0 || key.Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("an Ed25519 public key is required")
	}
	return key, nil
}

func parseSigningKey(value []byte, expected string) (ed25519.PrivateKey, error) {
	public, err := signingPublic(expected)
	if err != nil {
		return nil, err
	}
	raw, err := ssh.ParseRawPrivateKey(value)
	if err != nil {
		return nil, errors.New("invalid unencrypted signing key")
	}
	var private ed25519.PrivateKey
	switch key := raw.(type) {
	case *ed25519.PrivateKey:
		private = *key
	case ed25519.PrivateKey:
		private = key
	default:
		return nil, errors.New("only Ed25519 signing is supported")
	}
	if len(private) != ed25519.PrivateKeySize {
		clear(private)
		return nil, errors.New("invalid signing key")
	}
	derived := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
	defer clear(derived)
	actual, _ := ssh.NewPublicKey(derived.Public())
	if !bytes.Equal(derived, private) || !bytes.Equal(actual.Marshal(), public.Marshal()) {
		clear(private)
		return nil, errors.New("signing key does not match public identity")
	}
	return private, nil
}

func (s *Service) sign(ctx context.Context, request Request) Result {
	if request.Use != "ssh-sign" || len(request.Data) == 0 || len(request.Data) > MaxSecret {
		return Result{Error: "invalid signing request"}
	}
	if result := s.fetch(ctx, request.Key, false); result.Error != "" {
		return result
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.cache[request.Key]
	if s.closed || ctx.Err() != nil || !s.allowedLocked(request.Key) || !ok || !time.Now().Before(e.expires) {
		return Result{Error: "signing authority expired or was revoked"}
	}
	private, err := parseSigningKey(e.value.pages[:e.value.size], request.PublicKey)
	if err != nil {
		return Result{Error: "invalid signing identity"}
	}
	defer clear(private)
	return Result{Status: "signed", Signature: ed25519.Sign(private, request.Data)}
}
