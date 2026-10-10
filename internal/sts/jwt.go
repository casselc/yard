package sts

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

var b64 = base64.RawURLEncoding

// KeySigner is the narrow interface the minter needs. The TPM key and the
// software test key both implement it.
type KeySigner interface {
	Public() *rsa.PublicKey
	// SignPKCS1v15SHA256 signs a SHA-256 digest with RSASSA-PKCS1-v1_5.
	SignPKCS1v15SHA256(digest []byte) ([]byte, error)
}

// SoftSigner is a software RSA key, for tests and the no-TPM demo only.
type SoftSigner struct{ K *rsa.PrivateKey }

func (s SoftSigner) Public() *rsa.PublicKey { return &s.K.PublicKey }
func (s SoftSigner) SignPKCS1v15SHA256(d []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, s.K, crypto.SHA256, d)
}

// JWK is an RSA public JWK.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is a key set document.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Thumbprint returns the RFC 7638 SHA-256 JWK thumbprint, used as kid.
func Thumbprint(pub *rsa.PublicKey) string {
	n := b64.EncodeToString(pub.N.Bytes())
	e := b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	// Members in lexicographic order, no whitespace (RFC 7638 §3).
	canon := `{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`
	h := sha256.Sum256([]byte(canon))
	return b64.EncodeToString(h[:])
}

// PublicJWK converts a public key to a JWK.
func PublicJWK(pub *rsa.PublicKey) JWK {
	return JWK{Kty: "RSA", Kid: Thumbprint(pub), Use: "sig", Alg: "RS256",
		N: b64.EncodeToString(pub.N.Bytes()), E: b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes())}
}

// RSAPublic converts a JWK back to a public key.
func (j JWK) RSAPublic() (*rsa.PublicKey, error) {
	if j.Kty != "RSA" {
		return nil, fmt.Errorf("kty %q", j.Kty)
	}
	nb, err := b64.DecodeString(j.N)
	if err != nil {
		return nil, err
	}
	eb, err := b64.DecodeString(j.E)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}, nil
}

// SignJWT builds header.payload, signs it and returns the compact JWT.
func SignJWT(ks KeySigner, kid string, claims map[string]any) (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	pl, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString(hdr) + "." + b64.EncodeToString(pl)
	d := sha256.Sum256([]byte(signing))
	sig, err := ks.SignPKCS1v15SHA256(d[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	return signing + "." + b64.EncodeToString(sig), nil
}

// VerifyOptions are the relying-party checks applied by Verify.
type VerifyOptions struct {
	Issuer   string        // required iss
	Audience string        // if set, aud must equal it
	MaxTTL   time.Duration // if set, exp-iat must be <= it
	Now      time.Time     // if zero, expiry is not checked
}

// Verify checks an RS256 compact JWT against a JWKS and returns its claims.
// It is a plain stdlib verifier, independent of the signer code path.
func Verify(token string, set JWKS, o VerifyOptions) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt: not 3 parts")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt: header: %w", err)
	}
	var hdr struct{ Alg, Typ, Kid string }
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, fmt.Errorf("jwt: header: %w", err)
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("jwt: alg %q", hdr.Alg)
	}
	var pub *rsa.PublicKey
	for _, k := range set.Keys {
		if k.Kid == hdr.Kid {
			if pub, err = k.RSAPublic(); err != nil {
				return nil, err
			}
		}
	}
	if pub == nil {
		return nil, fmt.Errorf("jwt: kid %q not in jwks", hdr.Kid)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwt: sig: %w", err)
	}
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig); err != nil {
		return nil, fmt.Errorf("jwt: signature: %w", err)
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: payload: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(pb))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil {
		return nil, fmt.Errorf("jwt: payload: %w", err)
	}
	num := func(k string) (int64, error) {
		v, ok := claims[k].(json.Number)
		if !ok {
			return 0, fmt.Errorf("jwt: %s missing", k)
		}
		return v.Int64()
	}
	iat, err := num("iat")
	if err != nil {
		return nil, err
	}
	exp, err := num("exp")
	if err != nil {
		return nil, err
	}
	if o.Issuer != "" && claims["iss"] != o.Issuer {
		return nil, fmt.Errorf("jwt: iss %v", claims["iss"])
	}
	if o.Audience != "" && claims["aud"] != o.Audience {
		return nil, fmt.Errorf("jwt: aud %v", claims["aud"])
	}
	if o.MaxTTL > 0 && time.Duration(exp-iat)*time.Second > o.MaxTTL {
		return nil, fmt.Errorf("jwt: exp-iat %ds > %s", exp-iat, o.MaxTTL)
	}
	if !o.Now.IsZero() && o.Now.Unix() >= exp {
		return nil, errors.New("jwt: expired")
	}
	return claims, nil
}
