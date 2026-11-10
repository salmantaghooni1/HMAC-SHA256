# Binance-Style Request Authentication (HMAC + timestamp + recvWindow)

## Short explanation

There is no public information about how Binance connects to its internal databases. What is documented and well known is how Binance authenticates API requests, which is most likely what you mean. The method has three parts:

1. **HMAC-SHA256 signature:** The client signs the request parameters with its `secretKey`. The secret itself is never sent, only the signature.
2. **`timestamp`:** The time the request was created (in milliseconds) is part of the signed data.
3. **`recvWindow`:** The server accepts a request only if its timestamp is within this window of the current time. Binance's default is 5000 ms, but if you set it to 1000, the request is valid for only **one second**.

Because the timestamp is inside the signature, an attacker cannot change it. If they capture a request and replay it after one second, the server rejects it. This prevents **replay attacks**.

Binance also rejects requests whose timestamp is more than 1 second ahead of the server clock.

## Flow

```
Client                                      Server
  |  params + timestamp + recvWindow          |
  |  signature = HMAC(secret, params)         |
  |------------------------------------------>|
  |                                           | 1) Recompute and compare the signature
  |                                           | 2) now - timestamp <= recvWindow ?
  |                                           | 3) (optional) signature not seen before
  |<------------------------------------------|
```

## Go example

```go
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

// ---------- Shared ----------
func sign(secret, payload string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

// ---------- Client ----------
func buildRequest(secret string, params url.Values, recvWindowMs int64) string {
	params.Set("timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	params.Set("recvWindow", strconv.FormatInt(recvWindowMs, 10))
	query := params.Encode()
	return query + "&signature=" + sign(secret, query)
}

// ---------- Server ----------
type Server struct {
	secrets map[string]string // apiKey -> secret
	mu      sync.Mutex
	seen    map[string]int64 // signature -> expiry time (replay protection)
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

	// Split the signature from the rest of the query
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return err
	}
	gotSig := q.Get("signature")
	q.Del("signature")
	// Note: parameter order must match the client (Encode sorts alphabetically)
	payload := q.Encode()

	// 1) Verify the signature (constant-time comparison)
	expected := sign(secret, payload)
	if !hmac.Equal([]byte(expected), []byte(gotSig)) {
		return errors.New("bad signature")
	}

	// 2) Check the time window
	ts, _ := strconv.ParseInt(q.Get("timestamp"), 10, 64)
	recv, _ := strconv.ParseInt(q.Get("recvWindow"), 10, 64)
	if recv <= 0 || recv > 60000 {
		recv = 5000
	}
	now := time.Now().UnixMilli()
	if ts > now+1000 || now-ts > recv {
		return errors.New("timestamp outside recvWindow")
	}

	// 3) (Optional) block reuse of the same signature inside the window
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.seen { // purge expired entries
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

	req := buildRequest("my-secret", params, 1000) // valid for 1 second

	fmt.Println("immediate:", srv.Verify("my-api-key", req))  // <nil>
	fmt.Println("duplicate:", srv.Verify("my-api-key", req))  // replayed request

	time.Sleep(1500 * time.Millisecond)
	fmt.Println("after 1.5s:", srv.Verify("my-api-key", req)) // timestamp outside recvWindow
}
```

## Important notes

- Client and server clocks must be in sync (use NTP). If the client clock is behind, requests are rejected.
- `hmac.Equal` is used to prevent timing attacks.
- At scale, keep the `seen` cache in Redis with a TTL.
- Parameter order must be identical on the client and server when signing.
- This is an educational example and has not been run or tested; test it before using it in production.