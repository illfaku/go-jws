package jws

import (
	"crypto"
	"errors"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type Jws struct {
	method jwt.SigningMethod
	secret any
}

var ErrUnexpectedSigningMethod = errors.New("unexpected signing method")

func (jws *Jws) Sign(claims jwt.Claims) string {
	signed, err := jwt.NewWithClaims(jws.method, claims).SignedString(jws.secret)
	if err != nil {
		panic(err)
	}
	return signed
}

func (jws *Jws) Verify(signed string, claims jwt.Claims) error {
	_, err := jwt.ParseWithClaims(signed, claims, func(t *jwt.Token) (any, error) {
		if jws.method != t.Method {
			return nil, ErrUnexpectedSigningMethod
		}
		if signer, ok := jws.secret.(crypto.Signer); ok {
			return signer.Public(), nil
		}
		return jws.secret, nil
	})
	if err != nil {
		return err
	}
	return nil
}

func New(method jwt.SigningMethod, secret any) *Jws {
	return &Jws{method, secret}
}

func NewFromPem(method jwt.SigningMethod, key []byte) *Jws {
	var pk any
	var err error
	switch method.(type) {
	case *jwt.SigningMethodECDSA:
		pk, err = jwt.ParseECPrivateKeyFromPEM(key)
	case *jwt.SigningMethodEd25519:
		pk, err = jwt.ParseEdPrivateKeyFromPEM(key)
	case *jwt.SigningMethodRSA:
		pk, err = jwt.ParseRSAPrivateKeyFromPEM(key)
	default:
		err = ErrUnexpectedSigningMethod
	}
	if err != nil {
		panic(err)
	}
	return New(method, pk)
}

func NewFromPemFile(method jwt.SigningMethod, path string) *Jws {
	key, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return NewFromPem(method, key)
}
