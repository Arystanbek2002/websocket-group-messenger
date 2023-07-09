package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	websocketUpgrader = websocket.Upgrader{
		CheckOrigin:     checkOrigin,
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
)

type Manager struct {
	clients ClientList
	sync.RWMutex
	handlers map[string]EventHandler
	server   *APIServer
}

func NewManager(ctx context.Context, server *APIServer) *Manager {
	m := &Manager{
		clients:  make(ClientList),
		handlers: make(map[string]EventHandler),
		server:   server,
	}
	m.setupEventHandlers()
	return m
}

func (m *Manager) setupEventHandlers() {
	m.handlers[EventSendMessage] = m.SendMessage
}

func (m *Manager) SendMessage(event Event, c *Client) error {
	var chatEvent SendMessageEvent
	if err := json.Unmarshal(event.Payload, &chatEvent); err != nil {
		return fmt.Errorf("bad payload: %v", err)
	}

	direct, err := m.server.store.GetDirectByID(chatEvent.DirectID)
	if err != nil {
		return err
	}
	if c.id != direct.FirstUser && c.id != direct.SecondUser {
		return fmt.Errorf("bad request")
	}

	message := NewMessage(c.id, direct.ID, chatEvent.Message)
	if err := m.server.store.CreateMessage(message); err != nil {
		return err
	}

	var newMessage NewMessageEvent

	newMessage.Sent = time.Now()
	newMessage.Message = chatEvent.Message
	newMessage.From = c.username

	data, err := json.Marshal(&newMessage)
	if err != nil {
		return fmt.Errorf("marshal error: %v", err)
	}

	outgoingEvent := Event{
		Type:    EventNewMessagge,
		Payload: data,
	}
	for clients := range c.manager.clients {
		if clients.id == direct.FirstUser || clients.id == direct.SecondUser {
			clients.egress <- outgoingEvent
		}
	}

	return nil
}
func (m *Manager) routeEvent(event Event, c *Client) error {
	if handler, ok := m.handlers[event.Type]; ok {
		if err := handler(event, c); err != nil {
			return err
		}
		return nil
	} else {
		return errors.New("there is no such event")
	}
}

func (m *Manager) serveWC(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("x-jwt")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tknStr := c.Value
	status, claims, err := verifyJWT(tknStr)
	if err != nil {
		w.WriteHeader(status)
		return
	}
	log.Println("New connection")
	conn, err := websocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err.Error())
		return
	}
	client := NewClient(conn, m, claims.ID, claims.Username)
	m.addClient(client)

	go client.readMessages()
	go client.writeMessages()
}

func (m *Manager) addClient(client *Client) {
	m.Lock()
	defer m.Unlock()

	m.clients[client] = true

}

func (m *Manager) removeClient(client *Client) {
	m.Lock()
	defer m.Unlock()

	if _, ok := m.clients[client]; ok {
		client.connection.Close()
		delete(m.clients, client)
	}

}

func checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	switch origin {
	case "http://localhost:8080":
		return true
	default:
		return false
	}
}
