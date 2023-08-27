package models

import (
	"time"
)

type UserRequest struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

type UserResponce struct {
	ID         int       `json:"id"`
	UserName   string    `json:"username"`
	Created_at time.Time `json:"created_at"`
}

type User struct {
	ID        int    `json:"id"`
	UserName  string `json:"username"`
	Password  string `json:"password"`
	CreatedAt time.Time
}

func NewUser(name, password string) *User {
	return &User{
		UserName:  name,
		Password:  password,
		CreatedAt: time.Now().Local().UTC(),
	}
}
