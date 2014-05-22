package token

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

type TokenData struct {
	EntryId string
	Auth    string
}

// SessionTokenData contains TokenDatas (ie a browser cookie)
type SessionToken interface {
	GetTokenData() (tokenData *TokenData, isNew bool, err error)
	SetTokenData(*TokenData) error
}

var AuthLen = sha256.Size
var EntryIdLen = sha256.Size
var EncodedAuthLen = base64.URLEncoding.EncodedLen(sha256.Size)
var EncodedEntryIdLen = base64.URLEncoding.EncodedLen(sha256.Size)

func NewTokenDataFromString(str string) *TokenData {
	return &TokenData{str[0:EncodedEntryIdLen], str[EncodedEntryIdLen:]}
}

func (t *TokenData) String() string {
	return t.EntryId + t.Auth
}

func (t *TokenData) Valid() error {
	if len(t.EntryId) != EncodedEntryIdLen && len(t.Auth) != EncodedAuthLen {
		return errors.New("SessionTokenData: invalid id")
	}
	return nil
}
