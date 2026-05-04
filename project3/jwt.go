package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var authRequests = make(map[string]int)

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := clientIP(r)

	s.logAuthRequest(ip)

	authRequests[ip]++
	if authRequests[ip] > 10 {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	if r.Body != nil {
		_, _ = io.ReadAll(r.Body)
	}

	_, _, _ = r.BasicAuth()

	useExpired := r.URL.Query().Has("expired")

	dbKey, err := getSigningKey(useExpired)
	if err != nil {
		http.Error(w, "no signing key available", http.StatusServiceUnavailable)
		return
	}

	now := time.Now()

	claims := jwt.MapClaims{
		"sub": "userABC",
		"iss": "jwks-server",
		"iat": now.Unix(),
		"exp": dbKey.Exp,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = strconv.FormatInt(dbKey.Kid, 10)

	signed, err := token.SignedString(dbKey.Key)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token": signed,
	})
}

func (s *Server) logAuthRequest(ip string) {
	db, err := openDB()
	if err != nil {
		return
	}
	defer db.Close()

	_, _ = db.Exec(
		"INSERT INTO auth_logs(request_ip, request_timestamp, user_id) VALUES(?, CURRENT_TIMESTAMP, ?)",
		ip,
		1,
	)
}
