package jwks

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

type algorithmProvider struct {
	providers.RuntimeCryptoProvider
	key       *rsa.PublicKey
	algorithm string
}

func (p algorithmProvider) GetPublicKeys(context.Context, providers.PublicKeyFilter) ([]providers.PublicKeyInfo, error) {
	return []providers.PublicKeyInfo{{PublicKey: p.key, Algorithm: p.algorithm, Thumbprint: "test-key"}}, nil
}

func TestProviderRSAAlgorithmSelectsAndVerifiesSignedJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []string{"PS256", "RS256", "RS512"} {
		t.Run(algorithm, func(t *testing.T) {
			service := newJWKSService(algorithmProvider{key: &key.PublicKey, algorithm: algorithm})
			published, serviceErr := service.GetJWKS(context.Background())
			if serviceErr != nil || len(published.Keys) != 1 {
				t.Fatal("public key unavailable")
			}
			jwk := published.Keys[0]
			if jwk.Alg != algorithm {
				t.Fatal("JWKS algorithm does not match provider signing algorithm")
			}
			n, err := base64.RawURLEncoding.DecodeString(jwk.N)
			if err != nil {
				t.Fatal(err)
			}
			e, err := base64.RawURLEncoding.DecodeString(jwk.E)
			if err != nil {
				t.Fatal(err)
			}
			publicKey := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
			token := jwt.NewWithClaims(jwt.GetSigningMethod(algorithm), jwt.MapClaims{"sub": "synthetic-subject"})
			token.Header["kid"] = "test-key"
			encoded, err := token.SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := jwt.Parse(encoded, func(token *jwt.Token) (any, error) {
				if token.Header["kid"] != jwk.Kid || token.Method.Alg() != jwk.Alg {
					return nil, errors.New("no matching signing key")
				}
				return publicKey, nil
			}, jwt.WithValidMethods([]string{algorithm}))
			if err != nil || !parsed.Valid {
				t.Fatal("published key cannot select and verify emitted JWT")
			}
		})
	}
	for _, algorithm := range []string{"HS256", "RSA-OAEP-256", "unknown"} {
		published, err := newJWKSService(algorithmProvider{key: &key.PublicKey, algorithm: algorithm}).GetJWKS(context.Background())
		if err == nil || published != nil {
			t.Fatal("incompatible provider algorithm must not be advertised")
		}
	}
}
