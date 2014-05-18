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

func (m *MapSessionStore) FindEntry(key string) (*SessionEntry, bool, error) {
	if entry, ok := m.data[key]; ok {
		return entry, true, nil
	}
	return nil, false, nil
}

func (m *MapSessionStore) AddEntry(key string, entry *SessionEntry) error {
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
