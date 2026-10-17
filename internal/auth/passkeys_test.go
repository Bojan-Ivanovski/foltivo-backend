package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/Bojan-Ivanovski/foltivo-backend/internal/testutil"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

func TestPasskeyRelyingPartyConfiguration(t *testing.T) {
	s := NewService(nil, nil)
	if err := s.ConfigurePasskeys("http://localhost:4173"); err != nil {
		t.Fatal("localhost configuration rejected")
	}
	if err := s.ConfigurePasskeys("http://127.0.0.1:4173"); err == nil {
		t.Fatal("numeric relying party ID accepted")
	}
}

func TestIntegrationPasskeyCeremonyBoundaries(t *testing.T) {
	pool := testutil.Database(t)
	ctx := context.Background()
	s := NewService(NewStore(pool), fastPasswords(t))
	secrets, _ := NewSecrets(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	s.ConfigureEmail(&EmailDelivery{Secrets: secrets})
	if err := s.ConfigurePasskeys("http://localhost:4173"); err != nil {
		t.Fatal(err)
	}
	if err := s.Register(ctx, "peer", "Passkey Person", "passkey@example.com", testPassword); err != nil {
		t.Fatal(err)
	}
	pending := mustLogin(t, s, "passkey@example.com")
	if _, err := s.BeginPasskey(ctx, pending, "peer", "registration", "Device"); err == nil {
		t.Fatal("unverified enrollment allowed")
	}
	_, _ = pool.Exec(ctx, "UPDATE users SET email_verified=true")
	current := mustLogin(t, s, "passkey@example.com")
	options, err := s.BeginPasskey(ctx, current, "peer", "registration", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(options)
	var object struct {
		PublicKey struct {
			Challenge              string `json:"challenge"`
			AuthenticatorSelection struct {
				UV string `json:"userVerification"`
				RK string `json:"residentKey"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	if json.Unmarshal(encoded, &object) != nil || object.PublicKey.Challenge == "" || (object.PublicKey.AuthenticatorSelection.UV != "required" || object.PublicKey.AuthenticatorSelection.RK != "required") {
		t.Fatal("registration did not require user verification")
	}
	// A different browser cannot consume this session's ceremony.
	other := mustLogin(t, s, "passkey@example.com")
	_, err = s.FinishPasskey(ctx, other, "peer", "registration", []byte(`{}`))
	assertStatus(t, err, 401)
	var count int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM auth_ceremonies WHERE session_id=$1", current.ID).Scan(&count)
	if count != 1 {
		t.Fatal("wrong browser consumed another ceremony")
	}
	_, err = s.FinishPasskey(ctx, current, "peer", "registration", []byte(`{}`))
	assertStatus(t, err, 401)
	shape := ""
	assertionShape := func(value any) string {
		encoded, _ := json.Marshal(value)
		var data map[string]any
		if json.Unmarshal(encoded, &data) != nil {
			t.Fatal("invalid assertion JSON")
		}
		public, ok := data["publicKey"].(map[string]any)
		if !ok {
			t.Fatal("missing publicKey")
		}
		if _, exists := public["allowCredentials"]; exists {
			t.Fatal("public assertion exposed credential IDs/count")
		}
		delete(public, "challenge")
		normalized, _ := json.Marshal(data)
		return string(normalized)
	}
	for _, email := range []string{"unknown@example.com", "passkey@example.com"} {
		anonymous := mustSession(t, s, "")
		options, err := s.BeginPasskey(ctx, anonymous, "peer", "login", email)
		if err != nil {
			t.Fatal("passkey begin disclosed missing account or method")
		}
		if shape == "" {
			shape = assertionShape(options)
		} else if assertionShape(options) != shape {
			t.Fatal("unknown and password-only assertion shapes differ")
		}
		_, err = s.FinishPasskey(ctx, anonymous, "peer", "login", []byte(`{}`))
		assertStatus(t, err, 401)
	}
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM auth_ceremonies WHERE session_id=$1", current.ID).Scan(&count)
	if count != 0 {
		t.Fatal("invalid finish was not single use")
	}
	if _, err = s.BeginPasskey(ctx, current, "peer", "registration", "Laptop"); err != nil {
		t.Fatal(err)
	}
	_, _ = pool.Exec(ctx, "UPDATE auth_ceremonies SET expires_at=now()-interval '1 second'")
	_, err = s.FinishPasskey(ctx, current, "peer", "registration", []byte(`{}`))
	assertStatus(t, err, 401)
	// Fixture credential only exercises begin/storage; positive signatures are
	// verified independently using Chromium's CTAP2 virtual authenticator.
	a, err := s.store.account(ctx, "passkey@example.com")
	if err != nil {
		t.Fatal(err)
	}
	credential := &wa.Credential{ID: []byte("fixture-credential"), PublicKey: []byte("not-a-signing-key")}
	stored, err := s.credentialBytes(a.ID, credential)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) == string(credential.PublicKey) {
		t.Fatal("credential was not encrypted")
	}
	_, err = pool.Exec(ctx, "INSERT INTO auth_passkeys(user_id,credential_id,credential,name) VALUES($1,$2,$3,$4)", a.ID, credential.ID, stored, "Fixture")
	if err != nil {
		t.Fatal(err)
	}
	anon := mustSession(t, s, "")
	options, err = s.BeginPasskey(ctx, anon, "peer", "login", a.Email)
	if err != nil {
		t.Fatal(err)
	}
	if assertionShape(options) != shape {
		t.Fatal("enrolled assertion disclosed account or credential metadata")
	}
	_, err = s.FinishPasskey(ctx, anon, "peer", "login", []byte(`{"id":"Zml4dHVyZS1jcmVkZW50aWFs","rawId":"Zml4dHVyZS1jcmVkZW50aWFs","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AA","signature":"AA"}}`))
	assertStatus(t, err, 401)
	security, err := s.Security(ctx, current)
	if err != nil || len(security.Passkeys) != 1 {
		t.Fatal("credential inventory unavailable")
	}
	if err = s.RemovePasskey(ctx, other, security.Passkeys[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Session(ctx, current.Token, "peer", false); err == nil {
		t.Fatal("factor removal did not revoke other sessions")
	}
}
