package main

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type DBKey struct {
	Kid int64
	Key *rsa.PrivateKey
	Exp int64
}

func openDB() (*sql.DB, error) {
	return sql.Open("sqlite3", "totally_not_my_privateKeys.db")
}

func parsePEMPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func getSigningKey(expired bool) (*DBKey, error) {
	db, err := openDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	now := time.Now().Unix()

	var row *sql.Row
	if expired {
		row = db.QueryRow(
			"SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
			now,
		)
	} else {
		row = db.QueryRow(
			"SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1",
			now,
		)
	}

	var kid int64
	var pemData []byte
	var exp int64

	if err := row.Scan(&kid, &pemData, &exp); err != nil {
		return nil, err
	}

	privateKey, err := parsePEMPrivateKey(pemData)
	if err != nil {
		return nil, err
	}

	return &DBKey{
		Kid: kid,
		Key: privateKey,
		Exp: exp,
	}, nil
}

func getValidPublicKeys() ([]DBKey, error) {
	db, err := openDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	now := time.Now().Unix()

	rows, err := db.Query(
		"SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid ASC",
		now,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []DBKey

	for rows.Next() {
		var kid int64
		var pemData []byte
		var exp int64

		if err := rows.Scan(&kid, &pemData, &exp); err != nil {
			return nil, err
		}

		privateKey, err := parsePEMPrivateKey(pemData)
		if err != nil {
			return nil, err
		}

		keys = append(keys, DBKey{
			Kid: kid,
			Key: privateKey,
			Exp: exp,
		})
	}

	return keys, rows.Err()
}
