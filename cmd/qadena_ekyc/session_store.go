package main

import (
	"fmt"
	"sync"
	"time"
)

// SessionStore stores referenceID to sessionID with expiration
type ExpirySessionStore struct {
	data map[string]string
	mu   sync.Mutex
}

// NewSessionStore initializes the session store
func NewExpirySessionStore() *ExpirySessionStore {
	return &ExpirySessionStore{
		data: make(map[string]string),
	}
}

// Set sets a referenceID to sessionID with a timeout
func (s *ExpirySessionStore) Set(referenceID, sessionID string, duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[referenceID]; exists {
		fmt.Printf("ReferenceID %s already exists\n", referenceID)
		return
	}

	// Set the referenceID to sessionID
	s.data[referenceID] = sessionID

	// Print the referenceID and sessionID
	fmt.Printf("ReferenceID %s set to SessionID %s\n", referenceID, sessionID)

	// Schedule removal after the duration
	go func() {
		time.Sleep(duration)
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.data, referenceID)
		fmt.Printf("ReferenceID %s expired and removed\n", referenceID)
	}()
}

// Get retrieves the sessionID for a given referenceID
func (s *ExpirySessionStore) Get(referenceID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sessionID, exists := s.data[referenceID]
	return sessionID, exists
}

/*
func main() {

	// Add referenceID to sessionID with a 10-second expiration
	store.Set("ref123", "sessionABC", 10*time.Second)

	// Fetch the sessionID
	sessionID, exists := store.Get("ref123")
	if exists {
		fmt.Printf("SessionID for ref123: %s\n", sessionID)
	} else {
		fmt.Println("SessionID for ref123 not found")
	}

	// Wait for more than 10 seconds to see the expiration
	time.Sleep(12 * time.Second)

	// Try to fetch the sessionID again after expiration
	sessionID, exists = store.Get("ref123")
	if exists {
		fmt.Printf("SessionID for ref123: %s\n", sessionID)
	} else {
		fmt.Println("SessionID for ref123 not found (expired)")
	}
}
*/
