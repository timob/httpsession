package mapstore

import (
	. "github.com/timob/httpsession/store"
	"sync"
	"time"
)

type MapSessionStore struct {
	data map[string]*SessionEntry
	*sync.Mutex
}

func NewMapSessionStore() *MapSessionStore {
	return &MapSessionStore{make(map[string]*SessionEntry), &sync.Mutex{}}
}

func (m *MapSessionStore) FetchEntry(key string) (*SessionEntry, error) {
	if entry, ok := m.data[key]; ok {
		return entry, nil
	}
	return nil, nil
}

func (m *MapSessionStore) SetEntry(key string, entry *SessionEntry) error {
	m.Lock()
	defer m.Unlock()

	if e, ok := m.data[key]; ok {
		*e = *entry
	} else {
		m.data[key] = entry
	}
	if len(m.data) > 1000 {
		for k, entry := range m.data {
			if time.Now().After(entry.SessionExpiry) {
				delete(m.data, k)
			}
		}
	}
	return nil
}
