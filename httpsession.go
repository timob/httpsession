// HTTP session package
package httpsession

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	. "github.com/timob/httpsession/store"
	. "github.com/timob/httpsession/token"
	"time"
)

// Session store has methods for accessing sessions.
type SessionDB struct {
	SessionStore
	SessionTimeout time.Duration // maximum time between requests in session
	TokenTimeout   time.Duration // timeout after which subsequent requests will receive new token
}

// Session can be used to get/set values for the session
type Session struct {
	Values       map[string]interface{}
	id           *sessionId
	readEntry    *SessionEntry
	SecondaryKey *string // if not nil, store can use this as a second lookup key
}

type sessionId struct {
	EntryId      string
	tokenCounter int
}

var DefaultSessionTimeout time.Duration = time.Minute * 10
var DefaultTokenTimeout time.Duration = DefaultSessionTimeout

// retryTimeout Small duration after token timeout, where old token will be honored.
// It is to allow for first reply(s) after token change to be lost.
var retryTimeout time.Duration = time.Minute * 1

func newSession() *Session {
	return &Session{make(map[string]interface{}), nil, nil, nil}
}

// GetSession returns a the session specified by token in t. If t is empty or
// session has expired or token is incorrect returns new session.
func (s *SessionDB) GetSession(t SessionToken) (*Session, error) {
	if t == nil {
		return nil, errors.New("SessionStore.GetSession: SessionTokenContainer is nil")
	}

	token, err := t.GetTokenData()
	if err != nil {
		return nil, err
	}
	if token == nil {
		return newSession(), nil
	}
	if err = token.Valid(); err != nil {
		return nil, err
	}

	entry, err := s.FetchEntry(token.EntryId)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return newSession(), nil
	}

	if time.Now().After(entry.SessionExpiry) {
		return newSession(), nil
	}

	if token.Token != entry.CorrectToken() {
		if !(entry.IsCorrectPreviousToken(token.Token) && time.Now().Before(entry.TokenStart.Add(retryTimeout))) {
			return newSession(), nil
		}
	}

	currentTokenCounter := entry.TokenCounter
	if time.Now().After(entry.TokenStart.Add(s.TokenTimeout)) {
		currentTokenCounter++
	}

	var vals map[string]interface{}
	err = gob.NewDecoder(bytes.NewReader(entry.Value)).Decode(&vals)
	if err != nil {
		return nil, err
	}

	return &Session{vals, &sessionId{token.EntryId, currentTokenCounter}, entry, entry.SecondaryKey}, nil
}

// Save session, store resulting token in t
func (s *SessionDB) SaveSession(session *Session, t SessionToken) error {
	if session == nil {
		return errors.New("SessionStore.Save: session is nil")
	}

	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(session.Values)
	if err != nil {
		return err
	}

	var id *sessionId
	var tokenStart time.Time
	var secret string
	if session.id == nil {
		entryIdBytes, err := generateRand(EntryIdLength)
		if err != nil {
			return err
		}
		id = &sessionId{base64.URLEncoding.EncodeToString(entryIdBytes), 0}
		secretBytes, err := generateRand(EntryIdLength)
		if err != nil {
			return err
		}
		secret = base64.URLEncoding.EncodeToString(secretBytes)
		tokenStart = time.Now()
	} else {
		id = session.id
		if id.tokenCounter > session.readEntry.TokenCounter {
			tokenStart = time.Now()
		} else {
			tokenStart = session.readEntry.TokenStart
		}
		secret = session.readEntry.Secret
	}

	err = s.SetEntry(id.EntryId, &SessionEntry{
		buf.Bytes(),
		time.Now().Add(s.SessionTimeout),
		tokenStart,
		secret,
		id.tokenCounter,
		session.SecondaryKey,
	})
	if err != nil {
		return err
	}

	token := base64.URLEncoding.EncodeToString(sha256Sum(
		fmt.Sprintf("%s%d", secret, id.tokenCounter),
	))

	return t.SetTokenData(&TokenData{id.EntryId, token})
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
