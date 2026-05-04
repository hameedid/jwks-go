package main

import (
	"log"
	"net/http"
)

func main() {
	s, err := NewServer()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Starting server on :8080")
	err = http.ListenAndServe(":8080", s.routes())
	if err != nil {
		log.Fatal(err)
	}
}
