package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq"
)

type Storage interface {
	CreateUser(*User) error
	GetUser(int) (*User, error)
	GetUsers() ([]*User, error)
	LoginUser(string, string) (*User, error)
	CreateDirect(*Direct) error
	GetDirectByUsers(int, int) (*Direct, error, bool)
	GetDirectByID(int) (*Direct, error)
	GetDirects() ([]*Direct, error)
	CreateMessage(*Message) error
	GetMessagesByDirect(int) ([]*Message, error)
	GetMessages() ([]*Message, error)
}

type PostrgresStore struct {
	db *sql.DB
}

func newPostgresStore() (*PostrgresStore, error) {
	connStr := fmt.Sprintf("postgres://%s:%s@my_postrgres:5432/%s?sslmode=disable", os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"))
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	return &PostrgresStore{db: db}, nil
}

func (p *PostrgresStore) Init() error {
	return p.CreateUserTable()
}

func (p *PostrgresStore) CreateUserTable() error {
	query := `create table if not exists users(
		id serial primary key,
		username varchar(50) UNIQUE,
		password varchar(450),
		created_at timestamp
	)`

	_, err := p.db.Exec(query)
	if err != nil {
		return err
	}

	query = `create table if not exists directs(
		id serial primary key,
		first_user INT references users(id),
		second_user INT references users(id),
		created_at timestamp
	)`
	_, err = p.db.Exec(query)
	if err != nil {
		return err
	}

	query = `create table if not exists messages(
		id serial primary key,
		from_id INT references users(id),
		direct_id INT references directs(id),
		value varchar(45000),
		created_at timestamp
	)`
	_, err = p.db.Exec(query)

	return err
}

func (p *PostrgresStore) CreateUser(user *User) error {
	password, err := HashPassword(user.Password)
	if err != nil {
		return err
	}
	_, err = p.db.Query("insert into users (username, password, created_at) values($1, $2, $3)", user.UserName, password, user.CreatedAt)
	if err != nil {
		return err
	}
	return nil
}

func (p *PostrgresStore) CreateDirect(direct *Direct) error {
	_, err := p.db.Query("insert into directs (first_user, second_user, created_at) values($1, $2, $3)", direct.FirstUser, direct.SecondUser, direct.CreatedAt)
	if err != nil {
		return err
	}
	return nil
}

func (p *PostrgresStore) CreateMessage(message *Message) error {
	_, err := p.db.Query("insert into messages (from_id, direct_id, value, created_at) values($1, $2, $3, $4)", message.From, message.DirectID, message.Value, message.CreatedAt)
	if err != nil {
		return err
	}
	return nil
}

func (p *PostrgresStore) GetUser(id int) (*User, error) {
	rows, err := p.db.Query("select * from users where id = $1", id)
	if err != nil {
		return nil, err
	}
	user := new(User)
	if rows.Next() {
		if err := rows.Scan(&user.ID, &user.UserName, &user.Password, &user.CreatedAt); err != nil {
			return nil, err
		}
		return user, nil
	}
	return nil, fmt.Errorf("account not found")
}

func (p *PostrgresStore) GetDirectByUsers(id1, id2 int) (*Direct, error, bool) {
	if id1 > id2 {
		temp := id1
		id1 = id2
		id2 = temp
	}
	rows, err := p.db.Query("select * from directs where first_user = $1 and second_user = $2", id1, id2)
	if err != nil {
		return nil, err, false
	}
	direct := new(Direct)
	if rows.Next() {
		if err := rows.Scan(&direct.ID, &direct.FirstUser, &direct.SecondUser, &direct.CreatedAt); err != nil {
			return nil, err, false
		}
		return direct, nil, false
	}
	return nil, fmt.Errorf("direct not found"), true
}

func (p *PostrgresStore) GetDirectByID(id int) (*Direct, error) {
	rows, err := p.db.Query("select * from directs where id = $1", id)
	if err != nil {
		return nil, err
	}
	direct := new(Direct)
	if rows.Next() {
		if err := rows.Scan(&direct.ID, &direct.FirstUser, &direct.SecondUser, &direct.CreatedAt); err != nil {
			return nil, err
		}
		return direct, nil
	}
	return nil, fmt.Errorf("direct not found")
}

func (p *PostrgresStore) GetMessagesByDirect(id int) ([]*Message, error) {
	rows, err := p.db.Query("select * from messages where direct_id = $1", id)
	if err != nil {
		return nil, err
	}
	messages := []*Message{}
	for rows.Next() {
		message := new(Message)
		if err := rows.Scan(&message.ID, &message.From, &message.DirectID, &message.Value, &message.CreatedAt); err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	return messages, nil
}

func (p *PostrgresStore) GetMessages() ([]*Message, error) {
	rows, err := p.db.Query("select * from messages")
	if err != nil {
		return nil, err
	}
	messages := []*Message{}
	for rows.Next() {
		message := new(Message)
		if err := rows.Scan(&message.ID, &message.From, &message.DirectID, &message.Value, &message.CreatedAt); err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	return messages, nil
}

func (p *PostrgresStore) GetUsers() ([]*User, error) {
	rows, err := p.db.Query("select * from users")
	if err != nil {
		return nil, err
	}
	users := []*User{}
	for rows.Next() {
		user := new(User)
		if err := rows.Scan(&user.ID, &user.UserName, &user.Password, &user.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func (p *PostrgresStore) GetDirects() ([]*Direct, error) {
	rows, err := p.db.Query("select * from directs")
	if err != nil {
		return nil, err
	}
	directs := []*Direct{}
	for rows.Next() {
		direct := new(Direct)
		if err := rows.Scan(&direct.ID, &direct.FirstUser, &direct.SecondUser, &direct.CreatedAt); err != nil {
			return nil, err
		}
		directs = append(directs, direct)
	}
	return directs, nil
}

func (p *PostrgresStore) LoginUser(username, password string) (*User, error) {
	rows, err := p.db.Query("select * from users where username = $1", username)
	if err != nil {
		return nil, err
	}
	user := new(User)
	if rows.Next() {
		if err := rows.Scan(&user.ID, &user.UserName, &user.Password, &user.CreatedAt); err != nil {
			return nil, err
		}
		err := CheckPasswordHash(password, user.Password)
		if err != nil {
			return nil, err
		}
		return user, nil
	}
	return nil, fmt.Errorf("credentials are wrong")
}
