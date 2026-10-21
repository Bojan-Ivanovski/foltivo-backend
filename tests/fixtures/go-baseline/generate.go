// Regenerate using the baseline go.mod/go.sum as documented in README.md.
// The scalar 1 key is deliberately public synthetic TEST material.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

func main() {
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult([]byte{1})
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: big.NewInt(1)}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	mode, _ := cbor.CanonicalEncOptions().EncMode()
	cose, err := mode.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x.FillBytes(make([]byte, 32)), -3: y.FillBytes(make([]byte, 32))})
	if err != nil {
		panic(err)
	}
	credential := wa.Credential{
		ID: []byte("foltivo-go-baseline-credential"), PublicKey: cose,
		AttestationFormat: "none", Transport: []protocol.AuthenticatorTransport{protocol.Internal},
		Flags:         wa.CredentialFlags{UserPresent: true, UserVerified: true},
		Authenticator: wa.Authenticator{SignCount: 1},
		Attestation:   wa.CredentialAttestation{ClientDataJSON: []byte("preserved-historical-client-data"), PublicKeyAlgorithm: -7},
	}
	ceremony := wa.SessionData{Challenge: base64.RawURLEncoding.EncodeToString([]byte("synthetic-go-challenge-32-bytes!!")), RelyingPartyID: "localhost", UserVerification: protocol.VerificationRequired}
	result := map[string]any{"baseline": "6fc5145a7f0983dd1a3c92a44216ec9de041df55", "credential": credential, "ceremony": ceremony, "privateKey": base64.StdEncoding.EncodeToString(pkcs8)}
	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
}
