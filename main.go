package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"
)

func sign(secret, payload string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

// ---------- client ----------
func buildRequest(secret string, params url.Values, recvWindowMs int64) string {
	params.Set("timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	params.Set("recvWindow", strconv.FormatInt(recvWindowMs, 10))
	query := params.Encode()
	return query + "&signature=" + sign(secret, query)
}

// ---------- server ----------
type Server struct {
	secrets map[string]string // apiKey -> secret
	mu      sync.Mutex
	seen    map[string]int64 // signature
}

func NewServer() *Server {
	return &Server{
		secrets: map[string]string{"my-api-key": "my-secret"},
		seen:    map[string]int64{},
	}
}

func (s *Server) Verify(apiKey, rawQuery string) error {
	secret, ok := s.secrets[apiKey]
	if !ok {
		return errors.New("invalid api key")
	}

	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return err
	}
	gotSig := q.Get("signature")
	q.Del("signature")
	payload := q.Encode()

	expected := sign(secret, payload)
	if !hmac.Equal([]byte(expected), []byte(gotSig)) {
		return errors.New("bad signature")
	}

	ts, _ := strconv.ParseInt(q.Get("timestamp"), 10, 64)
	recv, _ := strconv.ParseInt(q.Get("recvWindow"), 10, 64)
	if recv <= 0 || recv > 60000 {
		recv = 5000
	}
	now := time.Now().UnixMilli()
	if ts > now+1000 || now-ts > recv {
		return errors.New("timestamp outside recvWindow")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.seen {
		if exp < now {
			delete(s.seen, k)
		}
	}
	if _, dup := s.seen[gotSig]; dup {
		return errors.New("replayed request")
	}
	s.seen[gotSig] = ts + recv

	return nil
}

func main() {
	srv := NewServer()

	params := url.Values{}
	params.Set("symbol", "BTCUSDT")
	params.Set("side", "BUY")

	req := buildRequest("my-secret", params, 1000)


	time.Sleep(1500 * time.Millisecond)
}