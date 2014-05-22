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
	"github.com/timob/httpsession/store"
	"github.com/timob/httpsession/token"
	"time"
)

var DefaultSessionTimeout time.Duration = time.Minute * 10
var DefaultAuthTimeout time.Duration = DefaultSessionTimeout

// retryTimeout Small duration after token timeout, where old token will be honored.
// It is to allow for first reply(s) after token change to be lost.
var retryTimeout time.Duration = time.Minute * 1

type entryInfo struct {
	Values        map[string]interface{}
	AuthStart     time.Time
	SecretStr     string //[32]byte
	SecretCounter uint
}

func (s *entryInfo) AuthStr() string {
	return base64.URLEncoding.EncodeToString(sha256Sum(
		fmt.Sprintf("%s%d", s.SecretStr, s.SecretCounter),
	))
}

// store.SessionData <-> entryInfo
type entryInfoStore struct {
	*store.SessionDataStore
	//encoder
}

func (s *entryInfoStore) FindEntryInfo(key string) (info *entryInfo, ok bool, err error) {
	entry, ok, err := s.FindSessionData(key)
	if err != nil || !ok {
		return
	}

	info = new(entryInfo)
	err = gob.NewDecoder(bytes.NewReader(entry.Data)).Decode(&info)
	return
}

func (s *entryInfoStore) SaveEntryInfo(key string, info *entryInfo) (err error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err = enc.Encode(info)
	if err != nil {
		return
	}

	err = s.SaveSessionData(key, &store.SessionData{buf.Bytes()})
	return
}

// key -> category
type category struct {
	*entryInfoStore
	Name string
}

func (c *category) FindEntryInfo(key string) (info *entryInfo, ok bool, err error) {
	return c.entryInfoStore.FindEntryInfo(c.Name + key)
}

func (c *category) SaveEntryInfo(key string, info *entryInfo) (err error) {
	return c.entryInfoStore.SaveEntryInfo(c.Name+key, info)
}

type sessionInfo struct {
	entryInfo
	UpdateAuthStartTimeOnSave bool
}

// entryInfo <-> sessionInfo
type sessionInfoStore struct {
	*category
	AuthTimeout time.Duration
}

func (s *sessionInfoStore) FindSessionInfo(key string, auth string) (session *sessionInfo, ok bool, err error) {
	entry, ok, err := s.FindEntryInfo(key)
	if err != nil || !ok {
		return
	}

	if auth == entry.AuthStr() {
		session = &sessionInfo{entryInfo: *entry}

		if time.Now().After(session.AuthStart.Add(s.AuthTimeout)) {
			session.SecretCounter++
			session.UpdateAuthStartTimeOnSave = true
		}

		return
	} else if entry.SecretCounter != 0 {
		entry.SecretCounter--
		if auth == entry.AuthStr() && time.Now().Before(entry.AuthStart.Add(retryTimeout)) {
			entry.SecretCounter++
			session = &sessionInfo{entryInfo: *entry}
			return
		}
	}

	err = errors.New("AuthSessionCategory: Authentication failed")
	return
}

func (s *sessionInfoStore) SaveSessionInfo(key string, session *sessionInfo) (err error) {
	if session.UpdateAuthStartTimeOnSave || (session.AuthStart == time.Time{}) {
		session.AuthStart = time.Now()
	}

	return s.SaveEntryInfo(key, &session.entryInfo)
}

// Exported

type Session struct {
	sessionInfo
	infoStore       *sessionInfoStore
	key             string
	stoken          token.SessionToken
	tokenHasBeenSet bool
}

func (s *Session) SetToken() error {
	s.tokenHasBeenSet = true
	return s.stoken.SetTokenData(&token.TokenData{s.key, s.AuthStr()})
}

func (s *Session) Save() (err error) {
	if !s.tokenHasBeenSet {
		err = s.SetToken()
		if err != nil {
			return
		}
		s.tokenHasBeenSet = true
	}
	return s.infoStore.SaveSessionInfo(s.key, &s.sessionInfo)
}

func (s *Session) Values() map[string]interface{} {
	return s.sessionInfo.Values
}

func (s *Session) Id() string {
	return s.key
}

// Token <-> Session
type SessionCategory struct {
	infoStore *sessionInfoStore
}

func NewSessionCategory(name string, s store.SessionEntryStore, sessionTimeout, authTimeout time.Duration) *SessionCategory {
	return &SessionCategory{&sessionInfoStore{
		&category{
			&entryInfoStore{
				&store.SessionDataStore{
					s,
					sessionTimeout,
				},
			},
			name,
		},
		authTimeout,
	}}
}

func (s *SessionCategory) GetSession(t token.SessionToken) (*Session, error) {
	if t == nil {
		return nil, errors.New("TokenAccessedSession.GetSession: token.SessionToken is nil")
	}

	tokenData, empty, err := t.GetTokenData()
	if err != nil {
		return nil, err
	}
	if empty {
		return newSession(s, t)
	}

	if err = tokenData.Valid(); err != nil {
		return nil, err
	}

	session, found, err := s.infoStore.FindSessionInfo(tokenData.EntryId, tokenData.Auth)
	if err != nil {
		return nil, err
	}

	if found {
		return &Session{*session, s.infoStore, tokenData.EntryId, t, false}, nil
	} else {
		return newSession(s, t)
	}
}

func (s *SessionCategory) FindSessionValuesById(id string) (vals map[string]interface{}, ok bool, err error) {
	session, ok, err := s.infoStore.FindEntryInfo(id)
	if err != nil || !ok {
		return
	}
	vals = session.Values
	return
}

func newSession(s *SessionCategory, t token.SessionToken) (*Session, error) {
	entryIdBytes, err := generateRand(token.EntryIdLen)
	if err != nil {
		return nil, err
	}
	secretBytes, err := generateRand(token.AuthLen)
	if err != nil {
		return nil, err
	}

	session := &Session{
		sessionInfo: sessionInfo{
			entryInfo: entryInfo{
				Values:    make(map[string]interface{}),
				SecretStr: base64.URLEncoding.EncodeToString(secretBytes),
			},
		},
		infoStore: s.infoStore,
		key:       base64.URLEncoding.EncodeToString(entryIdBytes),
		stoken:    t,
	}

	return session, nil
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
