package main

import (
	"time"
)

type Message struct {
	ID        int    `json:"id"`
	From      int    `json:"from"`
	DirectID  int    `json:"direct_id"`
	Value     string `json:"value"`
	CreatedAt time.Time
}

func NewMessage(from int, direct int, value string) *Message {
	return &Message{
		From:      from,
		DirectID:  direct,
		Value:     value,
		CreatedAt: time.Now().Local().UTC(),
	}
}
