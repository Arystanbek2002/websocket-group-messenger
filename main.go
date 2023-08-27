package main

import (
	"log"

	"github.com/arystanbek2002/websocket-group-messenger/api"
	"github.com/arystanbek2002/websocket-group-messenger/storage"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()
	store, err := storage.NewPostgresStore()
	if err != nil {
		log.Fatal(err)
	}

	if err := store.Init(); err != nil {
		log.Fatal(err)
	}

	server := api.NewAPIServer(":8080", store)
	server.Run()
}
