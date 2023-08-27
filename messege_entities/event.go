package message_entities

import (
	"encoding/json"
	"time"
)

type Event struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type EventHandler func(event Event, c *Client) error

const (
	EventSendMessage = "send_message"
	EventNewMessagge = "new_message"
)

type SendMessageEvent struct {
	Message  string `json:"message"`
	From     string `json:"from"`
	DirectID int    `json:"direct_id"`
}

type NewMessageEvent struct {
	SendMessageEvent
	Sent time.Time `json:"sent"`
}
