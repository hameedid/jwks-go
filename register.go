package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

func randomString(size int) (string, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func hashPassword(password string) (string, error) {
	salt, err := randomString(16)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		[]byte(salt),
		1,
		64*1024,
		4,
		32,
	)

	return salt + "$" + hex.EncodeToString(hash), nil
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	password := uuid.New().String()
	if err != nil {
		http.Error(w, "Could not generate password", http.StatusInternalServerError)
		return
	}

	passwordHash, err := hashPassword(password)
	if err != nil {
		http.Error(w, "Could not hash password", http.StatusInternalServerError)
		return
	}

	db, err := openDB()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	_, err = db.Exec(
		"INSERT INTO users(username, password_hash, email) VALUES(?, ?, ?)",
		req.Username,
		passwordHash,
		req.Email,
	)

	if err != nil {
		http.Error(w, "User already exists or database error", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(map[string]string{
		"password": password,
	})
}
