// HTTP session package
package httpsession

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/timob/httpsession/store"
	"github.com/timob/httpsession/token"
	"log"
	"time"
)

// retryTimeout Small duration after authToken timeout, where old token will be honored.
// It is to allow for first reply(s) after token change to be lost.
var retryTimeout time.Duration = time.Minute * 1

type randomKey struct {
	session *sessionHandle
}

func (r *randomKey) GenerateSessionKey() (key string, err error) {
	keyBytes := make([]byte, sha256.Size)
	_, err = rand.Read(keyBytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(keyBytes), nil
}

type sessionData struct {
	key  string
	Data []byte
	store.SessionEntryStore
	SessionTimeout time.Duration
	session        *sessionHandle
}

func (s *sessionData) SetSessionTimeout(t time.Duration) {
	s.SessionTimeout = t
}

func (s *sessionData) SetStore(e store.SessionEntryStore) {
	s.SessionEntryStore = e
}

func (s *sessionData) SetKey(k string) {
	s.key = k
}

func (s *sessionData) Key() string {
	s.session.SetLastError(nil)
	return s.key
}

func (s *sessionData) LoadSession() (ok bool, err error) {
	entry, ok, err := s.FindEntry(s.key)
	if err != nil {
		return
	}

	if !ok || time.Now().After(entry.SessionExpiry) {
		return false, nil
	}

	s.Data = entry.Data
	err = s.session.Decode(s.Data)
	return
}

func (s *sessionData) NewSession() (err error) {
	s.key, err = s.session.GenerateSessionKey()
	if err != nil {
		return
	}
	s.session.NewSessionValues()
	return
}

func (s *sessionData) SaveSession() (err error) {
	err = s.session.Encode(&s.Data)
	if err != nil {
		return
	}

	return s.AddEntry(s.key, &store.SessionEntry{s.Data, time.Now().Add(s.SessionTimeout)})
}

type sessionGob struct {
	Info    interface{}
	session *sessionHandle
}

func (s *sessionGob) Decode(data []byte) (err error) {
	err = gob.NewDecoder(bytes.NewReader(data)).Decode(&s.Info)
	if err != nil {
		return
	}
	return s.session.LoadSessionValues(s.Info)
}

func (s *sessionGob) Encode(dataPtr *[]byte) (err error) {
	s.session.SaveSessionValues(&s.Info)
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err = enc.Encode(&s.Info)
	if err != nil {
		return
	}

	*dataPtr = buf.Bytes()
	return
}

type sessionJSON struct {
	values struct {
		Values map[string]interface{}
		Nest   interface{}
	}
	session *sessionHandle
}

func (s *sessionJSON) Decode(data []byte) (err error) {
	err = json.Unmarshal(data, &s.values)
	if err != nil {
		return
	}
	return s.session.LoadSessionValues(s.values)
}

func (s *sessionJSON) Encode(dataPtr *[]byte) (err error) {
	var i interface{}
	s.session.SaveSessionValues(&i)
	v := i.(struct {
		Values map[string]interface{}
		Nest   interface{}
	})
	jb, err := json.Marshal(v)
	if err != nil {
		return
	}
	*dataPtr = jb
	return
}

type authSessionJSON struct {
	values struct {
		Values map[string]interface{}
		Nest   interface{}
	}
	values2 struct {
		Values map[string]interface{}
		Auth   struct {
			AuthStart     time.Time
			SecretStr     string //[32]byte
			SecretCounter uint
			Nest          interface{}
		}
	}
	session *sessionHandle
}

func (s *authSessionJSON) Decode(data []byte) (err error) {
	err = json.Unmarshal(data, &s.values2)
	if err != nil {
		return
	}
	s.values.Values = s.values2.Values
	s.values.Nest = s.values2.Auth

	return s.session.LoadSessionValues(s.values)
}

func (s *authSessionJSON) Encode(dataPtr *[]byte) (err error) {
	var i interface{}
	s.session.SaveSessionValues(&i)
	s.values = i.(struct {
		Values map[string]interface{}
		Nest   interface{}
	})
	s.values2.Values = s.values.Values
	s.values2.Auth = s.values.Nest.(struct {
		AuthStart     time.Time
		SecretStr     string
		SecretCounter uint
		Nest          interface{}
	})
	jb, err := json.Marshal(s.values2)
	if err != nil {
		return
	}
	*dataPtr = jb
	return
}

type sessionEncoder interface {
	Decode([]byte) error
	Encode(*[]byte) error
}

type encodeLog struct {
	sessionEncoder
}

func (e *encodeLog) Encode(dataPtr *[]byte) (err error) {
	err = e.sessionEncoder.Encode(dataPtr)
	if err != nil {
		return
	}
	log.Printf("session encoding: %s", *dataPtr)
	return
}

func (e *encodeLog) Decode(data []byte) (err error) {
	err = e.sessionEncoder.Decode(data)
	if err != nil {
		return
	}
	log.Printf("session decoding: %s", data)
	return
}

type sessionValues struct {
	values struct {
		Values map[string]interface{}
		Nest   interface{}
	}
	session *sessionHandle
}

func (s *sessionValues) LoadSessionValues(values interface{}) (err error) {
	if v, ok := values.(struct {
		Values map[string]interface{}
		Nest   interface{}
	}); ok {
		s.values = v
	} else {
		return fmt.Errorf("unexpected type %T", values)
	}

	return
}

func (s *sessionValues) SaveSessionValues(valuesStore *interface{}) {
	*valuesStore = s.values
}

func (s *sessionValues) NewSessionValues() {
	s.values.Values = make(map[string]interface{})
}

func (s *sessionValues) SessionNest() interface{} {
	return s.values.Nest
}

func (s *sessionValues) SetSessionNest(i interface{}) {
	s.values.Nest = i
}

func (s *sessionValues) Values() map[string]interface{} {
	return s.values.Values
}

func (s *sessionValues) Clear() {
	s.NewSessionValues()
}

func (s *sessionValues) SetVar(key string, i interface{}) {
	s.values.Values[key] = i
}

func (s *sessionValues) GetVal(key string, dst interface{}) {
	i, ok := s.values.Values[key]
	if !ok {
		s.session.SetLastError(fmt.Errorf("unkown session value named: %s", key))
		return
	}

	f, ok := i.(float64)

	switch v := dst.(type) {
	case *int:
		if ok {
			*v = int(f)
		} else {
			*v, ok = i.(int)
		}
	case *uint:
		if ok {
			*v = uint(f)
		} else {
			*v, ok = i.(uint)
		}
	case *int64:
		if ok {
			*v = int64(f)
		} else {
			*v, ok = i.(int64)
		}
	case *uint64:
		if ok {
			*v = uint64(f)
		} else {
			*v, ok = i.(uint64)
		}
	case *float64:
		*v, ok = i.(float64)
	case *bool:
		*v, ok = i.(bool)
	case *string:
		*v, ok = i.(string)
	case *interface{}:
		*v = i
	}
	if !ok {
		s.session.SetLastError(fmt.Errorf("session value unkown type %T", i))
	}

	//	log.Printf("here2 %v, ok %v", *val.(*int), ok)
	return
}

func (s *sessionValues) IntVar(key string) (v int) {
	s.GetVal(key, &v)
	return
}

func (s *sessionValues) Int64Var(key string) (v int64) {
	s.GetVal(key, &v)
	return
}

func (s *sessionValues) UintVar(key string) (v uint) {
	s.GetVal(key, &v)
	return
}

func (s *sessionValues) Uint64Var(key string) (v uint64) {
	s.GetVal(key, &v)
	return
}

func (s *sessionValues) Float64Var(key string) (v float64) {
	s.GetVal(key, &v)
	return
}

func (s *sessionValues) BoolVar(key string) (v bool) {
	s.GetVal(key, &v)
	return
}

func (s *sessionValues) StringVar(key string) (v string) {
	s.GetVal(key, &v)
	return
}

func (s *sessionValues) Var(key string) (v interface{}) {
	s.GetVal(key, &v)
	return
}

func init() {
	gob.Register((sessionValues{}).values)
}

// entryInfo <-> sessionInfo
type sessionAuth struct {
	Auth struct {
		AuthStart     time.Time
		SecretStr     string //[32]byte
		SecretCounter uint
		Nest          interface{}
	}
	authStr                   string
	UpdateAuthStartTimeOnSave bool
	AuthTimeout               time.Duration
	session                   *sessionHandle
}

func (s *sessionAuth) AuthStr() string {
	return s.CalcAuth(0)
}

func (s *sessionAuth) SetAuthStr(e string) {
	s.authStr = e
}

func (s *sessionAuth) SetAuthStrTimeout(t time.Duration) {
	s.AuthTimeout = t
}

func (s *sessionAuth) NewAuthSession() (err error) {
	s.Auth.SecretStr, err = s.session.GenerateSessionKey()
	return s.session.NewSession()
}

func (s *sessionAuth) LoadAuthSession() (ok bool, err error) {
	ok, err = s.session.LoadSession()
	if err != nil || !ok {
		return
	}

	nested := s.session.SessionNest()
	if v, ok := nested.(struct {
		AuthStart     time.Time
		SecretStr     string
		SecretCounter uint
		Nest          interface{}
	}); ok {
		s.Auth = v
	} else {
		return false, fmt.Errorf("unexpected type %T", nested)
	}

	if s.authStr == s.CalcAuth(0) {
		if time.Now().After(s.Auth.AuthStart.Add(s.AuthTimeout)) {
			s.Auth.SecretCounter++
			s.UpdateAuthStartTimeOnSave = true
		}
		ok = true
	} else if s.authStr == s.CalcAuth(-1) && time.Now().Before(s.Auth.AuthStart.Add(retryTimeout)) {
		ok = true
	} else {
		return false, errors.New("invalid authentication token")
	}

	return
}

func (s *sessionAuth) CalcAuth(mod int) string {
	counter := int(s.Auth.SecretCounter) + mod
	if counter < 0 {
		counter = 0
	}

	b := sha256.Sum256([]byte(fmt.Sprintf("%s%d", s.Auth.SecretStr, counter)))

	return base64.URLEncoding.EncodeToString(b[:])
}

func (s *sessionAuth) SaveAuthSession() (err error) {
	if s.UpdateAuthStartTimeOnSave || (s.Auth.AuthStart == time.Time{}) {
		s.Auth.AuthStart = time.Now()
	}

	s.session.SetSessionNest(s.Auth)
	return s.session.SaveSession()
}

func init() {
	s := &sessionAuth{}
	gob.Register(s.Auth)
}

type sessionError struct {
	lastErr error
}

func (s *sessionError) GetLastError() error {
	return s.lastErr
}

func (s *sessionError) SetLastError(e error) {
	s.lastErr = e
}

type session interface {
	sessionExternal
	SetKey(string)
	SetSessionTimeout(time.Duration)
	LoadSession() (bool, error)
	SaveSession() error
	NewSession() error
	GenerateSessionKey() (string, error)
	Decode(data []byte) (err error)
	Encode(dataPtr *[]byte) (err error)
	LoadSessionValues(values interface{}) (err error)
	SaveSessionValues(valuesStore *interface{})
	NewSessionValues()
	SessionNest() interface{}
	SetSessionNest(i interface{})
	SetLastError(error)
}

type sessionHandle struct {
	session
}

type authSession interface {
	session
	LoadAuthSession() (bool, error)
	SaveAuthSession() error
	NewAuthSession() error
	SetAuthStr(string)
	AuthStr() string
	SetAuthStrTimeout(time.Duration)
}

type sessionExternal interface {
	Key() string
	SetVar(key string, i interface{})
	IntVar(key string) (v int)
	Int64Var(key string) (v int64)
	UintVar(key string) (v uint)
	Uint64Var(key string) (v uint64)
	Float64Var(key string) (v float64)
	BoolVar(key string) (v bool)
	StringVar(key string) (v string)
	Var(key string) (v interface{})
	Values() map[string]interface{}
	Clear()
	GetLastError() error
}

// Exported
type Session struct {
	sessionExternal
	sessionInternal session
}

func (s *Session) Save(sessionTimeout time.Duration) {
	var err error
	s.sessionInternal.SetSessionTimeout(sessionTimeout)
	if v, ok := s.sessionInternal.(authSession); ok {
		err = v.SaveAuthSession()
	} else {
		err = s.sessionInternal.SaveSession()
	}
	s.sessionInternal.SetLastError(err)
}

func (s *Session) Recreate() (sessionIdToken token.Token) {
	key, err := s.sessionInternal.GenerateSessionKey()
	s.sessionInternal.SetLastError(err)
	if err != nil {
		return nil
	}
	s.sessionInternal.SetKey(key)
	return token.TokenStr(key)
}

func OpenSession(idToken token.Token, store store.SessionEntryStore) (sessionR *Session, sessionIdToken token.Token, err error) {
	var handle sessionHandle
	session := &struct {
		*sessionData
		sessionEncoder
		*sessionValues
		*randomKey
		*sessionError
	}{&sessionData{session: &handle}, &sessionJSON{session: &handle}, &sessionValues{session: &handle}, &randomKey{session: &handle}, &sessionError{}}
	handle.session = session

	session.SetKey(idToken.String())
	session.SetStore(store)
	ok, err := session.LoadSession()
	if err != nil {
		return
	}
	if !ok {
		err = session.NewSession()
		if err != nil {
			return
		}
	}

	return &Session{session, session}, token.TokenStr(session.Key()), nil
}

func OpenSessionWithAuth(idToken token.Token, authToken token.Token, authTokenTimeout time.Duration, store store.SessionEntryStore) (sessionR *Session, sessionIdToken token.Token, sessionAuthToken token.Token, err error) {
	var handle sessionHandle
	authSession := &struct {
		*sessionData
		sessionEncoder
		*sessionValues
		*randomKey
		*sessionError
		*sessionAuth
	}{&sessionData{session: &handle}, &authSessionJSON{session: &handle}, &sessionValues{session: &handle}, &randomKey{session: &handle}, &sessionError{}, &sessionAuth{session: &handle}}
	handle.session = authSession

	authSession.SetKey(idToken.String())
	authSession.SetStore(store)
	authSession.SetAuthStr(authToken.String())
	authSession.SetAuthStrTimeout(authTokenTimeout)
	ok, err := authSession.LoadAuthSession()
	if err != nil {
		return
	}
	if !ok {
		err = authSession.NewAuthSession()
		if err != nil {
			return
		}
	}

	return &Session{authSession, authSession}, token.TokenStr(authSession.Key()), token.TokenStr(authSession.AuthStr()), nil
}

func FindSessionValuesByKey(key string, store store.SessionEntryStore) (vals map[string]interface{}, ok bool, err error) {
	var handle sessionHandle
	session := &struct {
		*sessionData
		sessionEncoder
		*sessionValues
		*sessionError
		*randomKey
	}{&sessionData{session: &handle}, &sessionJSON{session: &handle}, &sessionValues{session: &handle}, &sessionError{}, nil}
	handle.session = session

	session.SetKey(key)
	session.SetStore(store)
	ok, err = session.LoadSession()
	if err != nil || !ok {
		return
	}
	return session.Values(), true, nil
}

// want func (s *Session) DurationSinceLastUpdate() time.Duration
