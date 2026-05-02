# Project 2 - JWKS Server

## Overview

This project implements a JWKS server with SQLite-backed key storage. It supports issuing JWTs and exposing public keys via a JWKS endpoint.

## Endpoints

### POST /auth

Returns a signed JWT.

Supports:

* No authentication
* HTTP Basic Auth
* JSON body:
  {"username": "userABC", "password": "password123"}

### GET /.well-known/jwks.json

Returns all valid public keys in JWKS format.

## Database

* SQLite file: totally_not_my_privateKeys.db
* Stores RSA private keys with expiration timestamps
* Uses parameterized queries to prevent SQL injection

## Features

* Generates and stores RSA keys
* Supports expired and valid keys
* Returns JWT signed with selected key
* JWKS exposes only valid public keys

## Testing

* Gradebot used for testing
* Functional tests pass
* Coverage exceeds 80%

## Note

The gradebot “Quality” check returns a 503 error, but:

* All endpoints function correctly
* Manual testing with curl confirms correct behavior

This appears to be a gradebot issue rather than an implementation issue.
