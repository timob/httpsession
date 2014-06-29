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
	"io"
	"log"
	"reflect"
	"time"
)

// retryTimeout Small duration after authToken timeout, where old token will be honored.
// It is to allow for first reply(s) after token change to be lost.
var retryTimeout time.Duration = time.Minute * 1

type randomKey struct {
	session session
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
	key string
	store.SessionEntryStore
	SessionTimeout time.Duration
	session        session
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

	buf := bytes.NewBuffer(entry.Data)
	s.session.NewDecoder(buf)

	err = s.session.LoadSessionValues()
	if err != nil {
		ok = false
	}
	return
}

func (s *sessionData) NewSession() (err error) {
	s.key, err = s.session.GenerateSessionKey()
	if err != nil {
		return
	}
	return s.session.NewSessionValues()
}

func (s *sessionData) SaveSession() (err error) {
	buf := new(bytes.Buffer)
	s.session.NewEncoder(buf)

	err = s.session.SaveSessionValues()
	if err != nil {
		return
	}

	err = s.session.FinishEncode()
	if err != nil {
		return
	}

	return s.AddEntry(s.key, &store.SessionEntry{buf.Bytes(), time.Now().Add(s.SessionTimeout)})
}

type sessionGob struct {
	enc *gob.Encoder
	dec *gob.Decoder
}

func (s *sessionGob) NewEncoder(w io.Writer) {
	s.enc = gob.NewEncoder(w)
}

func (s *sessionGob) Encode(v interface{}) error {
	return s.enc.Encode(v)
}

func (s *sessionGob) NewDecoder(r io.Reader) {
	s.dec = gob.NewDecoder(r)
}

func (s *sessionGob) Decode(v interface{}) error {
	return s.dec.Decode(v)
}

func (s *sessionGob) FinishEncode() error { return nil }

type sessionJSON struct {
	enc *json.Encoder
	dec *json.Decoder
}

func (s *sessionJSON) NewEncoder(w io.Writer) {
	s.enc = json.NewEncoder(w)
}

func (s *sessionJSON) Encode(v interface{}) error {
	return s.enc.Encode(v)
}

func (s *sessionJSON) NewDecoder(r io.Reader) {
	s.dec = json.NewDecoder(r)
}

func (s *sessionJSON) Decode(v interface{}) error {
	return s.dec.Decode(v)
}

func (s *sessionJSON) FinishEncode() error { return nil }

type sessionJSONObject struct {
	codec sessionJSON
	raw   map[string]json.RawMessage
	imap  map[string]interface{}
}

func (s *sessionJSONObject) NewEncoder(w io.Writer) {
	s.codec.NewEncoder(w)
	s.imap = make(map[string]interface{})
}

func (s *sessionJSONObject) Encode(v interface{}) (err error) {
	name, err := s.getValName(v)
	if err != nil {
		return
	}
	s.imap[name] = v
	return
}

func (s *sessionJSONObject) FinishEncode() (err error) {
	return s.codec.Encode(s.imap)
}

func (s *sessionJSONObject) NewDecoder(r io.Reader) {
	s.codec.NewDecoder(r)
	s.raw = make(map[string]json.RawMessage)
}

func (s *sessionJSONObject) Decode(v interface{}) (err error) {
	if len(s.raw) == 0 {
		err = s.codec.Decode(&s.raw)
		if err != nil {
			return
		}
	}
	name, err := s.getValName(v)
	if err != nil {
		return
	}

	if rawJson, ok := s.raw[name]; ok {
		err = json.NewDecoder(bytes.NewBuffer(rawJson)).Decode(v)
		if err != nil {
			return
		}
	} else {
		return fmt.Errorf("decode: can't find %s in json", name)
	}
	return
}

func (s *sessionJSONObject) getValName(v interface{}) (string, error) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr {
		return "", errors.New("encode: parameter must be a pointer to object")
	}
	t := reflect.Indirect(rv).Type()
	if t.Name() == "" {
		return "", errors.New("encode: object must have name")
	}
	return t.Name(), nil
}

type sessionCodecLog struct {
	sessionCodec
	buf *bytes.Buffer
}

func (s *sessionCodecLog) NewEncoder(w io.Writer) {
	s.buf = new(bytes.Buffer)
	m := io.MultiWriter(w, s.buf)
	s.sessionCodec.NewEncoder(m)
}

func (s *sessionCodecLog) FinishEncode() (err error) {
	err = s.sessionCodec.FinishEncode()
	if err != nil {
		return
	}
	buf := new(bytes.Buffer)
	json.Indent(buf, s.buf.Bytes(), "", "    ")
	log.Printf("encoding %s", buf.Bytes())
	return
}

type sessionValues struct {
	Values    map[string]interface{}
	Timestamp time.Time
	session   session `json:"-"`
}

func (s *sessionValues) LoadSessionValues() (err error) {
	return s.session.Decode(s)
}

func (s *sessionValues) SaveSessionValues() error {
	s.Timestamp = time.Now()
	return s.session.Encode(s)
}

func (s *sessionValues) NewSessionValues() (err error) {
	s.Values = make(map[string]interface{})
	return
}

func (s *sessionValues) SValues() map[string]interface{} {
	return s.Values
}

func (s *sessionValues) Clear() {
	s.NewSessionValues()
}

func (s *sessionValues) SetVar(key string, i interface{}) {
	s.Values[key] = i
}

func (s *sessionValues) GetVal(key string, dst interface{}) {
	i, ok := s.Values[key]
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

	s.session.SetLastError(nil)
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

func (s *sessionValues) DurationSinceLastUpdate() time.Duration {
	return time.Now().Sub(s.Timestamp)
}

func init() {
	gob.Register(sessionValues{})
}

type sessionAuthParam struct {
	authStr     string
	AuthTimeout time.Duration
}

func (s *sessionAuthParam) SetAuthStr(e string) {
	s.authStr = e
}

func (s *sessionAuthParam) AuthStr() string {
	return s.authStr
}

func (s *sessionAuthParam) SetAuthStrTimeout(t time.Duration) {
	s.AuthTimeout = t
}

func (s *sessionAuthParam) AuthStrTimeout() time.Duration {
	return s.AuthTimeout
}

// entryInfo <-> sessionInfo
type sessionAuth struct {
	AuthStart     time.Time
	SecretStr     string //[32]byte
	SecretCounter uint

	updateAuthStartTimeOnSave bool
	authSession               `json:"-"`
}

func (s *sessionAuth) NewSessionValues() (err error) {
	s.SecretStr, err = s.authSession.GenerateSessionKey()
	if err != nil {
		return
	}
	s.authSession.SetAuthStr(s.CalcAuth(0))
	return s.authSession.NewSessionValues()
}

func (s *sessionAuth) LoadSessionValues() (err error) {
	err = s.authSession.LoadSessionValues()
	if err != nil {
		return
	}

	err = s.authSession.Decode(s)
	if err != nil {
		return
	}

	if s.authSession.AuthStr() == s.CalcAuth(0) {
		if time.Now().After(s.AuthStart.Add(s.authSession.AuthStrTimeout())) {
			s.SecretCounter++
			s.updateAuthStartTimeOnSave = true
		}
		// ok
	} else if s.authSession.AuthStr() == s.CalcAuth(-1) && time.Now().Before(s.AuthStart.Add(retryTimeout)) {
		// ok
	} else {
		return errors.New("invalid authentication token")
	}

	s.authSession.SetAuthStr(s.CalcAuth(0))
	return
}

func (s *sessionAuth) CalcAuth(mod int) string {
	counter := int(s.SecretCounter) + mod
	if counter < 0 {
		counter = 0
	}

	b := sha256.Sum256([]byte(fmt.Sprintf("%s%d", s.SecretStr, counter)))

	return base64.URLEncoding.EncodeToString(b[:])
}

func (s *sessionAuth) SaveSessionValues() (err error) {
	if s.updateAuthStartTimeOnSave || (s.AuthStart == time.Time{}) {
		s.AuthStart = time.Now()
	}

	err = s.authSession.SaveSessionValues()
	if err != nil {
		return
	}
	return s.authSession.Encode(s)
}

func init() {
	s := &sessionAuth{}
	gob.Register(s)
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

type sessionEncoder interface {
	NewEncoder(w io.Writer)
	Encode(v interface{}) error
	FinishEncode() error
}

type sessionDecoder interface {
	NewDecoder(r io.Reader)
	Decode(v interface{}) error
}

type sessionCodec interface {
	sessionEncoder
	sessionDecoder
}

type session interface {
	sessionExternal
	SetKey(string)
	SetSessionTimeout(time.Duration)
	LoadSession() (bool, error)
	SaveSession() error
	NewSession() error
	GenerateSessionKey() (string, error)
	LoadSessionValues() (err error)
	SaveSessionValues() (err error)
	NewSessionValues() error
	SetLastError(error)
	SValues() map[string]interface{}
	sessionCodec
}

type sessionHandle struct {
	session
}

type authSession interface {
	session
	SetAuthStr(string)
	AuthStr() string
	SetAuthStrTimeout(time.Duration)
	AuthStrTimeout() time.Duration
}

type authSessionHandle struct {
	authSession
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
	Clear()
	GetLastError() error
	DurationSinceLastUpdate() time.Duration
}

// Exported
type Session struct {
	sessionExternal
	sessionInternal session
}

func (s *Session) Save(sessionTimeout time.Duration) {
	var err error
	s.sessionInternal.SetSessionTimeout(sessionTimeout)
	err = s.sessionInternal.SaveSession()
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

func (s *Session) Values() map[string]interface{} {
	return s.sessionInternal.SValues()
}

func OpenSession(idToken token.Token, store store.SessionEntryStore) (sessionR *Session, sessionIdToken token.Token, err error) {
	var handle sessionHandle
	session := &struct {
		*sessionData
		sessionCodec
		*sessionValues
		*randomKey
		*sessionError
	}{&sessionData{session: &handle}, &sessionJSONObject{}, &sessionValues{session: &handle}, &randomKey{session: &handle}, &sessionError{}}
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
	var handle authSessionHandle
	authSession := &struct {
		*sessionData
		*sessionAuthParam
		*sessionValues
		sessionCodec
		*randomKey
		*sessionError
	}{
		&sessionData{session: &sessionAuth{authSession: &handle}},
		&sessionAuthParam{},
		&sessionValues{session: &handle},
		&sessionJSONObject{},
		&randomKey{session: &handle},
		&sessionError{},
	}
	handle.authSession = authSession

	authSession.SetKey(idToken.String())
	authSession.SetStore(store)
	authSession.SetAuthStr(authToken.String())
	authSession.SetAuthStrTimeout(authTokenTimeout)
	ok, err := authSession.LoadSession()
	if err != nil {
		return
	}
	if !ok {
		err = authSession.NewSession()
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
		*sessionValues
		sessionCodec
		*sessionError
		*randomKey
	}{&sessionData{session: &handle}, &sessionValues{session: &handle}, &sessionJSONObject{}, &sessionError{}, nil}
	handle.session = session

	session.SetKey(key)
	session.SetStore(store)
	ok, err = session.LoadSession()
	if err != nil || !ok {
		return
	}
	return session.SValues(), true, nil
}
