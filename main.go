package main

import (
	"log"

	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()
	store, err := newPostgresStore()
	if err != nil {
		log.Fatal(err)
	}

	if err := store.Init(); err != nil {
		log.Fatal(err)
	}

	server := newAPIServer(":8080", store)
	server.Run()
}
