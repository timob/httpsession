package store

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

// Database interface to fetch/set session entries (eg using Mysql)
type SessionStore interface {
	FetchEntry(string) (*SessionEntry, error)
	SetEntry(string, *SessionEntry) error
}

// Session entry to be stored by backend.
type SessionEntry struct {
	Value         []byte
	SessionExpiry time.Time
	TokenStart    time.Time
	Secret        string //[32]byte
	TokenCounter  int
	SecondaryKey  *string
}

func (e *SessionEntry) CorrectToken() string {
	return base64.URLEncoding.EncodeToString(sha256Sum(
		fmt.Sprintf("%s%d", e.Secret, e.TokenCounter),
	))
}

func (e *SessionEntry) IsCorrectPreviousToken(token string) bool {
	counter := e.TokenCounter
	if counter == 0 {
		return false
	}
	counter--

	return token == base64.URLEncoding.EncodeToString(sha256Sum(
		fmt.Sprintf("%s%d", e.Secret, counter),
	))
}

func sha256Sum(input string) []byte {
	b := sha256.Sum256([]byte(input))
	return b[:]
}
