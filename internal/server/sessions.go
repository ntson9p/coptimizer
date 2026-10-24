package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"time"
)

// codeLifetime is how long a one-time launch code stays valid.
const codeLifetime = 2 * time.Minute

// sessions hands out session tokens in exchange for one-time launch codes.
// Launch links carry only the code, so a link left in the browser history is
// useless once the page has used it.
type sessions struct {
	mu     sync.Mutex
	now    func() time.Time
	codes  map[string]time.Time // code → expiry
	tokens map[string]bool
}

func newSessions(now func() time.Time) *sessions {
	return &sessions{now: now, codes: make(map[string]time.Time), tokens: make(map[string]bool)}
}

func (s *sessions) addCode(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = s.now().Add(codeLifetime)
}

func (s *sessions) newCode() string {
	code := RandomHex(16)
	s.addCode(code)
	return code
}

// exchange trades a launch code, which then stops working, for a new session
// token.
func (s *sessions) exchange(code string) (token string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.codes[code]
	delete(s.codes, code)
	if !ok || s.now().After(expiry) {
		return "", false
	}
	b := make([]byte, 32)
	rand.Read(b)
	token = base64.RawURLEncoding.EncodeToString(b)
	s.tokens[token] = true
	return token, true
}

func (s *sessions) valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return token != "" && s.tokens[token]
}

// RandomHex returns n random bytes as hex.
func RandomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
