package message_entities

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/arystanbek2002/websocket-group-messenger/models"
	"github.com/arystanbek2002/websocket-group-messenger/storage"
	jwt "github.com/golang-jwt/jwt/v4"
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
	storage  storage.Storage
}

func NewManager(ctx context.Context, storage storage.Storage) *Manager {
	m := &Manager{
		clients:  make(ClientList),
		handlers: make(map[string]EventHandler),
		storage:  storage,
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

	direct, err := m.storage.GetDirectByID(chatEvent.DirectID)
	if err != nil {
		return err
	}
	if c.id != direct.FirstUser && c.id != direct.SecondUser {
		return fmt.Errorf("bad request")
	}

	message := models.NewMessage(c.id, direct.ID, chatEvent.Message)
	if err := m.storage.CreateMessage(message); err != nil {
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

type Claims struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func verifyJWT(jwtString string) (int, *Claims, error) {
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(jwtString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return http.StatusUnauthorized, nil, err
		}
		return http.StatusBadRequest, nil, err
	}
	if !tkn.Valid {
		return http.StatusUnauthorized, nil, fmt.Errorf("not valid token")
	}
	return http.StatusOK, claims, nil
}

func (m *Manager) ServeWC(w http.ResponseWriter, r *http.Request) {
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
