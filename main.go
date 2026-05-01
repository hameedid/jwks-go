package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func initDB() {
	db, err := sql.Open("sqlite3", "totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	createTable := `
	CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		email TEXT UNIQUE,
		date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_login TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS auth_logs(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_ip TEXT NOT NULL,
		request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		user_id INTEGER,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);`

	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}
}

func saveKeyToDB(db *sql.DB, privateKey *rsa.PrivateKey, exp int64) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	pemData := pem.EncodeToMemory(pemBlock)

	encrypted, err := encrypt(pemData)
	if err != nil {
		return err
	}

	_, err = db.Exec(
		"INSERT INTO keys(key, exp) VALUES(?, ?)",
		encrypted,
		exp,
	)

	return err
}

func seedKeys() {
	db, err := sql.Open("sqlite3", "totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if err != nil {
		log.Fatal(err)
	}

	if count > 0 {
		return
	}

	validKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	expiredKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	validExp := time.Now().Add(1 * time.Hour).Unix()
	expiredExp := time.Now().Add(-1 * time.Hour).Unix()

	if err := saveKeyToDB(db, validKey, validExp); err != nil {
		log.Fatal(err)
	}

	if err := saveKeyToDB(db, expiredKey, expiredExp); err != nil {
		log.Fatal(err)
	}
}

func setupServer() (*Server, error) {
	initDB()
	seedKeys()
	return NewServer()
}

func main() {
	srv, err := setupServer()
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(srv.Run(":8080"))
}