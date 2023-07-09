package main

import (
	"time"
)

type Direct struct {
	ID         int `json:"id"`
	FirstUser  int `json:"first_user"`
	SecondUser int `json:"second_user"`
	CreatedAt  time.Time
}

func NewDirect(firstUser, secondUser int) *Direct {
	return &Direct{
		FirstUser:  firstUser,
		SecondUser: secondUser,
		CreatedAt:  time.Now().Local().UTC(),
	}
}
