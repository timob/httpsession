package token

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// SessionToken contains tokens (ie a browser cookie)
type SessionToken interface {
	GetTokenData() (token *TokenData, empty bool, err error)
	SetTokenData(*TokenData) error
}

// TokenData is used to access a session
type TokenData struct {
	EntryId string
	Token   string
}

var TokenLength = sha256.Size
var EntryIdLength = sha256.Size

func (s *TokenData) Valid() error {
	if len(s.EntryId) > base64.URLEncoding.EncodedLen(EntryIdLength) {
		return errors.New("SessionToken: invalid id")
	}
	if len(s.Token) > base64.URLEncoding.EncodedLen(TokenLength) {
		return errors.New("SessionToken: invalid token")
	}
	return nil
}
