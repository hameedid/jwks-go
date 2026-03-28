package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func resetTestDB(t *testing.T) {
	t.Helper()
	_ = os.Remove("totally_not_my_privateKeys.db")
	initDB()
	seedKeys()
}

func TestOpenDB(t *testing.T) {
	resetTestDB(t)

	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB failed: %v", err)
	}
	defer db.Close()
}

func TestGetSigningKeyValid(t *testing.T) {
	resetTestDB(t)

	k, err := getSigningKey(false)
	if err != nil {
		t.Fatalf("expected valid signing key, got error: %v", err)
	}
	if k == nil || k.Key == nil {
		t.Fatal("expected valid RSA key")
	}
}

func TestGetSigningKeyExpired(t *testing.T) {
	resetTestDB(t)

	k, err := getSigningKey(true)
	if err != nil {
		t.Fatalf("expected expired signing key, got error: %v", err)
	}
	if k == nil || k.Key == nil {
		t.Fatal("expected expired RSA key")
	}
}

func TestGetValidPublicKeys(t *testing.T) {
	resetTestDB(t)

	keys, err := getValidPublicKeys()
	if err != nil {
		t.Fatalf("expected valid public keys, got error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 valid key, got %d", len(keys))
	}
}

func TestParsePEMPrivateKeyValid(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	pemData := pem.EncodeToMemory(block)

	parsed, err := parsePEMPrivateKey(pemData)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected parsed key")
	}
}

func TestParsePEMPrivateKeyInvalid(t *testing.T) {
	_, err := parsePEMPrivateKey([]byte("invalid"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestSaveKeyToDB(t *testing.T) {
	resetTestDB(t)

	db, _ := openDB()
	defer db.Close()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	err := saveKeyToDB(db, key, 9999999999)
	if err != nil {
		t.Fatalf("saveKeyToDB failed: %v", err)
	}

	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)

	if count < 3 {
		t.Fatalf("expected >= 3 keys, got %d", count)
	}
}

func TestPublicJWKFromDBKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	dbKey := DBKey{
		Kid: 123,
		Key: key,
		Exp: 9999999999,
	}

	jwk := publicJWKFromDBKey(dbKey)

	if jwk.Kty != "RSA" {
		t.Fatal("wrong kty")
	}
	if jwk.Kid != "123" {
		t.Fatal("wrong kid")
	}
	if jwk.N == "" || jwk.E == "" {
		t.Fatal("missing key values")
	}
}

func TestB64Helpers(t *testing.T) {
	n := big.NewInt(123)
	if b64urlBigInt(n) == "" {
		t.Fatal("expected encoded N")
	}

	if b64urlInt(65537) == "" {
		t.Fatal("expected encoded E")
	}
}

func TestNewServer(t *testing.T) {
	s, err := NewServer()
	if err != nil || s == nil {
		t.Fatal("failed to create server")
	}
}

func TestHandleAuth(t *testing.T) {
	resetTestDB(t)

	s, _ := NewServer()

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr := httptest.NewRecorder()

	s.handleAuth(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var body map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &body)

	if body["token"] == "" {
		t.Fatal("missing token")
	}
}

func TestHandleAuthExpired(t *testing.T) {
	resetTestDB(t)

	s, _ := NewServer()

	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
	rr := httptest.NewRecorder()

	s.handleAuth(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestHandleAuthWrongMethod(t *testing.T) {
	resetTestDB(t)

	s, _ := NewServer()

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rr := httptest.NewRecorder()

	s.handleAuth(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestHandleJWKS(t *testing.T) {
	resetTestDB(t)

	s, _ := NewServer()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	s.handleJWKS(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var jwks JWKS
	_ = json.Unmarshal(rr.Body.Bytes(), &jwks)

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
}

func TestHandleJWKSWrongMethod(t *testing.T) {
	resetTestDB(t)

	s, _ := NewServer()

	req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	s.handleJWKS(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestRoutes(t *testing.T) {
	resetTestDB(t)

	s, _ := NewServer()

	handler := s.routes()
	if handler == nil {
		t.Fatal("expected handler")
	}
}
func TestInitDBCreatesTable(t *testing.T) {
	_ = os.Remove("totally_not_my_privateKeys.db")

	initDB()

	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB failed: %v", err)
	}
	defer db.Close()

	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'").Scan(&name)
	if err != nil {
		t.Fatalf("expected keys table to exist: %v", err)
	}

	if name != "keys" {
		t.Fatalf("expected table name keys, got %s", name)
	}
}

func TestSeedKeysNoDuplicateInsert(t *testing.T) {
	_ = os.Remove("totally_not_my_privateKeys.db")

	initDB()
	seedKeys()
	seedKeys()

	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB failed: %v", err)
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if err != nil {
		t.Fatalf("count query failed: %v", err)
	}

	if count != 2 {
		t.Fatalf("expected exactly 2 keys after reseed, got %d", count)
	}
}

func TestSetupServer(t *testing.T) {
	_ = os.Remove("totally_not_my_privateKeys.db")

	s, err := setupServer()
	if err != nil {
		t.Fatalf("setupServer failed: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil server")
	}

	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB failed: %v", err)
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if err != nil {
		t.Fatalf("count query failed: %v", err)
	}

	if count != 2 {
		t.Fatalf("expected 2 seeded keys, got %d", count)
	}
}
func TestSeedKeysInsertsValidAndExpired(t *testing.T) {
	_ = os.Remove("totally_not_my_privateKeys.db")

	initDB()
	seedKeys()

	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB failed: %v", err)
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 keys, got %d", count)
	}

	var validCount int
	err = db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp > strftime('%s','now')").Scan(&validCount)
	if err != nil {
		t.Fatalf("valid count query failed: %v", err)
	}
	if validCount != 1 {
		t.Fatalf("expected 1 valid key, got %d", validCount)
	}

	var expiredCount int
	err = db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp <= strftime('%s','now')").Scan(&expiredCount)
	if err != nil {
		t.Fatalf("expired count query failed: %v", err)
	}
	if expiredCount != 1 {
		t.Fatalf("expected 1 expired key, got %d", expiredCount)
	}
}

func TestHandleAuthResponseIsJSON(t *testing.T) {
	resetTestDB(t)

	s, err := NewServer()
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr := httptest.NewRecorder()

	s.handleAuth(rr, req)

	if rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("expected application/json, got %q", rr.Header().Get("Content-Type"))
	}
}
func TestRoutesServeAuth(t *testing.T) {
	resetTestDB(t)

	s, err := NewServer()
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr := httptest.NewRecorder()

	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestRoutesServeJWKS(t *testing.T) {
	resetTestDB(t)

	s, err := NewServer()
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestHandleJWKSResponseIsJSON(t *testing.T) {
	resetTestDB(t)

	s, err := NewServer()
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	s.handleJWKS(rr, req)

	if rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("expected application/json, got %q", rr.Header().Get("Content-Type"))
	}
}

func TestSeedKeysAddsTwoRowsOnFreshDB(t *testing.T) {
	_ = os.Remove("totally_not_my_privateKeys.db")

	initDB()
	seedKeys()

	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB failed: %v", err)
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if err != nil {
		t.Fatalf("count query failed: %v", err)
	}

	if count != 2 {
		t.Fatalf("expected 2 keys, got %d", count)
	}
}
func TestSetupServerExecution(t *testing.T) {
	_ = os.Remove("totally_not_my_privateKeys.db")

	s, err := setupServer()
	if err != nil {
		t.Fatalf("setupServer failed: %v", err)
	}

	if s == nil {
		t.Fatal("expected server instance")
	}
}
func TestRunFunction(t *testing.T) {
	s, err := NewServer()
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	go func() {
		_ = s.Run(":0") // random port
	}()
}
