package store

import (
	"time"
)

type SessionEntryStore interface {
	FindEntry(key string) (entry *SessionEntry, ok bool, err error)
	AddEntry(key string, entry *SessionEntry) error
}

type SessionEntry struct {
	Data          []byte
	SessionExpiry time.Time
}

type SessionData struct {
	Data []byte
}

// SessionEntry <-> SessionData
type SessionDataStore struct {
	SessionEntryStore
	SessionExpiry time.Duration
}

func (s *SessionDataStore) FindSessionData(key string) (d *SessionData, ok bool, err error) {
	entry, ok, err := s.FindEntry(key)
	if err != nil || !ok {
		return
	}

	if time.Now().After(entry.SessionExpiry) {
		return nil, false, nil
	}

	d = &SessionData{entry.Data}
	return
}

func (s *SessionDataStore) SaveSessionData(key string, d *SessionData) (err error) {
	err = s.AddEntry(
		key,
		&SessionEntry{d.Data, time.Now().Add(s.SessionExpiry)},
	)
	return
}
