// HTTP session package
package httpsession

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/timob/httpsession/store"
	"github.com/timob/httpsession/token"
	"time"
)

// SessionDB is a database of sessions
type SessionDB struct {
	store.SessionStore
	SessionTimeout time.Duration // maximum time between requests in session
	TokenTimeout   time.Duration // timeout after which subsequent requests will receive new token
}

// Session can be used to get/set values for the session
type Session struct {
	Values          map[string]interface{}
	id              *sessionId
	readEntry       *store.SessionEntry
	sessionDB       *SessionDB
	token           token.SessionToken
	tokenHasBeenSet bool
}

type sessionId struct {
	EntryId      string
	tokenCounter int
	secret       string
}

var DefaultSessionTimeout time.Duration = time.Minute * 10
var DefaultTokenTimeout time.Duration = DefaultSessionTimeout

// retryTimeout Small duration after token timeout, where old token will be honored.
// It is to allow for first reply(s) after token change to be lost.
var retryTimeout time.Duration = time.Minute * 1

func newSession(s *SessionDB, t token.SessionToken) (*Session, error) {
	entryIdBytes, err := generateRand(token.EntryIdLength)
	if err != nil {
		return nil, err
	}
	secretBytes, err := generateRand(token.EntryIdLength)
	if err != nil {
		return nil, err
	}
	id := &sessionId{
		base64.URLEncoding.EncodeToString(entryIdBytes),
		0,
		base64.URLEncoding.EncodeToString(secretBytes),
	}

	return &Session{make(map[string]interface{}), id, nil, s, t, false}, nil
}

// Set token data to identify this session. (SetToken() is called automatically
// by Save() if not called elsewhere.)
func (s *Session) SetToken() error {
	tokenStr := base64.URLEncoding.EncodeToString(sha256Sum(
		fmt.Sprintf("%s%d", s.id.secret, s.id.tokenCounter),
	))
	return s.token.SetTokenData(&token.TokenData{s.id.EntryId, tokenStr})
}

// GetSession returns the session specified by token t. If t is a new token or
// a session has expired or the token is incorrect, GetSession() returns a new
// session.
func (s *SessionDB) GetSession(t token.SessionToken) (*Session, error) {
	if t == nil {
		return nil, errors.New("SessionStore.GetSession: token.SessionTokenContainer is nil")
	}

	token, empty, err := t.GetTokenData()
	if err != nil {
		return nil, err
	}
	if empty {
		return newSession(s, t)
	}
	if err = token.Valid(); err != nil {
		return nil, err
	}

	entry, ok, err := s.FindEntry(token.EntryId)
	if err != nil {
		return nil, err
	}

	if !ok {
		return newSession(s, t)
	}

	if time.Now().After(entry.SessionExpiry) {
		return newSession(s, t)
	}

	if token.Token != entry.CorrectToken() {
		if !(entry.IsCorrectPreviousToken(token.Token) && time.Now().Before(entry.TokenStart.Add(retryTimeout))) {
			return newSession(s, t)
		}
	}

	currentTokenCounter := entry.TokenCounter
	if time.Now().After(entry.TokenStart.Add(s.TokenTimeout)) {
		currentTokenCounter++
	}

	vals, err := store.DecodeSessionValues(entry.Value)
	if err != nil {
		return nil, err
	}

	return &Session{
		vals,
		&sessionId{token.EntryId, currentTokenCounter, entry.Secret},
		entry,
		s,
		t,
		false,
	}, nil
}

// Save the session. (Calls SetToken() if it has not already been called.)
func (s *Session) Save() error {
	encoded, err := store.EncodeSessionValues(s.Values)
	if err != nil {
		return err
	}

	var tokenStart time.Time
	if s.readEntry == nil {
		tokenStart = time.Now()
	} else if s.id.tokenCounter > s.readEntry.TokenCounter {
		tokenStart = time.Now()
	} else {
		tokenStart = s.readEntry.TokenStart
	}

	err = s.sessionDB.AddEntry(s.id.EntryId, &store.SessionEntry{
		encoded,
		time.Now().Add(s.sessionDB.SessionTimeout),
		tokenStart,
		s.id.secret,
		s.id.tokenCounter,
	})
	if err != nil {
		return err
	}

	if !s.tokenHasBeenSet {
		return s.SetToken()
	}
	return nil
}

// Return Id for session
func (s *Session) SessionId() string {
	return s.id.EntryId
}

func generateRand(size int) ([]byte, error) {
	keyBytes := make([]byte, size)
	_, err := rand.Read(keyBytes)
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

func sha256Sum(input string) []byte {
	b := sha256.Sum256([]byte(input))
	return b[:]
}
