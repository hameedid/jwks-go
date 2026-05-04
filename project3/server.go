package main

import (
	"log"
	"net/http"
)

type Server struct{}

func NewServer() (*Server, error) {
	return &Server{}, nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("/auth", s.handleAuth)
	mux.HandleFunc("/register", s.handleRegister)

	return mux
}

func (s *Server) Run(addr string) error {
	log.Printf("Listening on %s", addr)
	return http.ListenAndServe(addr, s.routes())
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"keys":[]}`))
}
