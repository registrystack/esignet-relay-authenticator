package provider

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
)

type assertionKey struct {
	key      crypto.PrivateKey
	kid, alg string
}

func loadKey(path, kid string) (assertionKey, error) {
	bad := errors.New("Mint signing key invalid")
	b, e := readBounded(path, 64<<10)
	if e != nil {
		return assertionKey{}, bad
	}
	defer clear(b)
	var key crypto.PrivateKey
	alg := "RS256"
	if block, rest := pem.Decode(b); block != nil {
		if len(rest) != 0 {
			return assertionKey{}, bad
		}
		key, e = x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			key, e = x509.ParsePKCS1PrivateKey(block.Bytes)
		}
		if e != nil {
			return assertionKey{}, bad
		}
	} else {
		var j struct {
			Kty, Alg, Use, Kid, N, E, D, P, Q, DP, DQ, QI, Crv, X, Y string
			KeyOps                                                   []string `json:"key_ops"`
		}
		if json.Unmarshal(b, &j) != nil || j.Use != "" && j.Use != "sig" || blank(j.Kid) || kid != "" && kid != j.Kid {
			return assertionKey{}, bad
		}
		if len(j.KeyOps) > 0 && (len(j.KeyOps) != 1 || j.KeyOps[0] != "sign") {
			return assertionKey{}, bad
		}
		kid = j.Kid
		alg = j.Alg
		number := func(s string) *big.Int {
			v, err := base64.RawURLEncoding.DecodeString(s)
			if err != nil || len(v) == 0 {
				return nil
			}
			return new(big.Int).SetBytes(v)
		}
		if j.Kty == "RSA" && alg == "RS256" {
			n, ex, d, p, q := number(j.N), number(j.E), number(j.D), number(j.P), number(j.Q)
			if n == nil || ex == nil || !ex.IsInt64() || ex.Int64() > 1<<31-1 || d == nil || p == nil || q == nil || number(j.DP) == nil || number(j.DQ) == nil || number(j.QI) == nil {
				return assertionKey{}, bad
			}
			r := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: int(ex.Int64())}, D: d, Primes: []*big.Int{p, q}}
			if r.Validate() != nil {
				return assertionKey{}, bad
			}
			r.Precompute()
			if r.Precomputed.Dp.Cmp(number(j.DP)) != 0 || r.Precomputed.Dq.Cmp(number(j.DQ)) != 0 || r.Precomputed.Qinv.Cmp(number(j.QI)) != 0 {
				return assertionKey{}, bad
			}
			key = r
		} else if j.Kty == "EC" && alg == "ES256" && j.Crv == "P-256" {
			x, y, d := number(j.X), number(j.Y), number(j.D)
			curve := elliptic.P256()
			if x == nil || y == nil || d == nil || d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 || !curve.IsOnCurve(x, y) {
				return assertionKey{}, bad
			}
			dx, dy := curve.ScalarBaseMult(d.Bytes())
			if x.Cmp(dx) != 0 || y.Cmp(dy) != 0 {
				return assertionKey{}, bad
			}
			key = &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
		} else {
			return assertionKey{}, bad
		}
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 || k.Validate() != nil {
			return assertionKey{}, bad
		}
		k.Precompute()
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return assertionKey{}, bad
		}
		alg = "ES256"
	default:
		return assertionKey{}, bad
	}
	if blank(kid) {
		return assertionKey{}, bad
	}
	return assertionKey{key, kid, alg}, nil
}
func (k assertionKey) assertion(client, audience string, iat, exp int64) (string, error) {
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrUnavailable
	}
	head, _ := json.Marshal(map[string]any{"alg": k.alg, "typ": "JWT", "kid": k.kid})
	body, _ := json.Marshal(map[string]any{"iss": client, "sub": client, "aud": audience, "iat": iat, "exp": exp, "jti": base64.RawURLEncoding.EncodeToString(nonce)})
	input := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(input))
	var sig []byte
	var err error
	switch key := k.key.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	case *ecdsa.PrivateKey:
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, key, sum[:])
		if err == nil {
			sig = make([]byte, 64)
			r.FillBytes(sig[:32])
			s.FillBytes(sig[32:])
		}
	}
	if err != nil {
		return "", ErrUnavailable
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
