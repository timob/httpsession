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
