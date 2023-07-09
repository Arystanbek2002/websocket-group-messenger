package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

type APIServer struct {
	listenAddr string
	store      Storage
}

type APIError struct {
	Error string `json:"error"`
}

var (
	manager *Manager
)

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		log.Println(err)
	}
	return err
}

func WriteJSONlogin(w http.ResponseWriter, status int, v any, jwToken string, expirationTime time.Time) error {
	cookie := http.Cookie{
		Name:     "x-jwt",
		Value:    jwToken,
		Path:     "/",
		Expires:  expirationTime,
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, &cookie)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		log.Println(err)
	}
	return nil
}

type APIFunc func(w http.ResponseWriter, r *http.Request) error

func makeHTTPHandleFunc(f APIFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			WriteJSON(w, http.StatusBadRequest, APIError{Error: err.Error()})
		}
	}
}

func newAPIServer(listenAddr string, store Storage) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
		store:      store,
	}
}

func (s *APIServer) Run() {
	err := godotenv.Load(".env")

	if err != nil {
		log.Printf("Error loading .env file")
	}

	ctx := context.Background()

	router := mux.NewRouter()
	manager = NewManager(ctx, s)

	router.HandleFunc("/", makeHTTPHandleFunc(s.handleIndexPage))
	router.HandleFunc("/messenger/{id}", makeHTTPHandleFunc(s.handleMessengerPage))
	router.HandleFunc("/direct", makeHTTPHandleFunc(s.handleGetDirects))
	router.HandleFunc("/register", s.handleRegisterPage)
	router.HandleFunc("/registerUser", makeHTTPHandleFunc(s.handleCreateUser))
	router.HandleFunc("/ws", manager.serveWC)
	router.HandleFunc("/loginUser", makeHTTPHandleFunc(s.handleLogin))
	router.HandleFunc("/login", s.handleLoginPage)
	router.HandleFunc("/user", makeHTTPHandleFunc(s.handleUser))
	router.HandleFunc("/user/{id}", makeHTTPHandleFunc(s.handleGetUser))
	//router.HandleFunc("/sendmessage", makeHTTPHandleFunc(s.handleSendMessage))
	router.HandleFunc("/message", makeHTTPHandleFunc(s.handleGetMessages))

	log.Println("Server running on port " + s.listenAddr)

	http.ListenAndServe(s.listenAddr, router)
}

func (s *APIServer) handleUser(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "POST" {
		return s.handleCreateUser(w, r)
	} else if r.Method == "GET" {
		return s.handleGetUsers(w, r)
	}
	return fmt.Errorf("usupported method %s", r.Method)
}

type Claims struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func generateJWT(user *User) (string, time.Time, error) {
	expirationTime := time.Now().Add(10 * time.Minute)

	claims := &Claims{
		ID:       user.ID,
		Username: user.UserName,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return "", time.Now(), err
	}
	return tokenString, expirationTime, nil
}

func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) error {
	type loginResp struct {
		User *UserResponce `json:"user"`
		Jwt  string        `json:"jwt"`
	}

	req := new(UserRequest)

	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return err
	}

	user, err := s.store.LoginUser(req.UserName, req.Password)
	if err != nil {
		return err
	}

	resp := new(loginResp)

	jwToken, expirationTime, err := generateJWT(user)
	if err != nil {
		return err
	}

	userResp := new(UserResponce)
	userResp.ID = user.ID
	userResp.UserName = user.UserName
	userResp.Created_at = user.CreatedAt

	resp.User = userResp
	resp.Jwt = jwToken

	return WriteJSONlogin(w, http.StatusOK, resp, jwToken, expirationTime)
}

func (s *APIServer) handleGetUsers(w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie("x-jwt")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return err
		}
		w.WriteHeader(http.StatusBadRequest)
		return err
	}

	tknStr := c.Value
	status, _, err := verifyJWT(tknStr)
	if err != nil {
		w.WriteHeader(status)
		return err
	}

	users, err := s.store.GetUsers()
	if err != nil {
		return err
	}
	userResps := []*UserResponce{}
	for _, user := range users {
		userResp := new(UserResponce)
		userResp.ID = user.ID
		userResp.UserName = user.UserName
		userResp.Created_at = user.CreatedAt
		userResps = append(userResps, userResp)
	}
	w.WriteHeader(status)
	w.Write(getHtmlUsers(userResps))
	return nil
}

func (s *APIServer) handleGetDirects(w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie("x-jwt")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return err
		}
		w.WriteHeader(http.StatusBadRequest)
		return err
	}

	tknStr := c.Value
	status, _, err := verifyJWT(tknStr)
	if err != nil {
		w.WriteHeader(status)
		return err
	}

	directs, err := s.store.GetDirects()
	if err != nil {
		return err
	}
	return WriteJSON(w, http.StatusOK, directs)
}

func (s *APIServer) handleGetMessages(w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie("x-jwt")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return err
		}
		w.WriteHeader(http.StatusBadRequest)
		return err
	}

	tknStr := c.Value
	status, _, err := verifyJWT(tknStr)
	if err != nil {
		w.WriteHeader(status)
		return err
	}

	messages, err := s.store.GetMessages()
	if err != nil {
		return err
	}
	return WriteJSON(w, http.StatusOK, messages)
}

func (s *APIServer) handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write(GetHtmlRegister())
}

func (s *APIServer) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write(GetHtmlLogin())
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

func (s *APIServer) handleMessengerPage(w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie("x-jwt")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return err
		}
		w.WriteHeader(http.StatusBadRequest)
		return err
	}

	tknStr := c.Value
	status, claims, err := verifyJWT(tknStr)
	if err != nil {
		return err
	}

	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		return err
	}
	direct, err, isNotFound := s.store.GetDirectByUsers(id, claims.ID)

	if isNotFound {
		direct = NewDirect(0, 0)
		if id < claims.ID {
			direct.FirstUser = id
			direct.SecondUser = claims.ID
		} else if claims.ID < id {
			direct.FirstUser = claims.ID
			direct.SecondUser = id
		}
		err = s.store.CreateDirect(direct)
		if err != nil {
			return err
		}
		direct, err, _ = s.store.GetDirectByUsers(id, claims.ID)
	}
	if err != nil {
		return err
	}

	messages, err := s.store.GetMessagesByDirect(direct.ID)
	if err != nil {
		return err
	}

	users := make(map[int]*User)

	user, err := s.store.GetUser(direct.FirstUser)
	if err != nil {
		return err
	}
	users[user.ID] = user

	user, err = s.store.GetUser(direct.SecondUser)
	if err != nil {
		return err
	}
	users[user.ID] = user

	w.WriteHeader(status)
	w.Write(GetHtmlMessenger(messages, users, direct.ID))
	return nil
}

func (s *APIServer) handleIndexPage(w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie("x-jwt")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return err
		}
		w.WriteHeader(http.StatusBadRequest)
		return err
	}

	tknStr := c.Value
	status, _, err := verifyJWT(tknStr)
	if err != nil {
		return err
	}

	w.WriteHeader(status)
	w.Write(GetHtmlIndex())
	return nil
}

func (s *APIServer) handleGetUser(w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie("x-jwt")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return err
		}
		w.WriteHeader(http.StatusBadRequest)
		return err
	}

	tknStr := c.Value
	status, _, err := verifyJWT(tknStr)
	if err != nil {
		w.WriteHeader(status)
		return err
	}

	id, _ := strconv.Atoi(mux.Vars(r)["id"])
	user, err := s.store.GetUser(id)

	if err != nil {
		return err
	}

	userResp := new(UserResponce)
	userResp.ID = user.ID
	userResp.UserName = user.UserName
	userResp.Created_at = user.CreatedAt

	return WriteJSON(w, http.StatusOK, userResp)
}

func (s *APIServer) handleCreateUser(w http.ResponseWriter, r *http.Request) error {
	request := new(UserRequest)
	if err := json.NewDecoder(r.Body).Decode(request); err != nil {
		return err
	}

	user := NewUser(request.UserName, request.Password)
	if err := s.store.CreateUser(user); err != nil {
		return err
	}
	userResp := new(UserResponce)
	userResp.ID = user.ID
	userResp.UserName = user.UserName
	userResp.Created_at = user.CreatedAt

	return WriteJSON(w, http.StatusOK, userResp)
}

// func (s *APIServer) handleSendMessage(w http.ResponseWriter, r *http.Request) error {
// 	type SendMessageReq struct {
// 		DirectID int    `json:"direct_id"`
// 		Value    string `json:"value"`
// 	}

// 	c, err := r.Cookie("x-jwt")
// 	if err != nil {
// 		if err == http.ErrNoCookie {
// 			w.WriteHeader(http.StatusUnauthorized)
// 			return err
// 		}
// 		w.WriteHeader(http.StatusBadRequest)
// 		return err
// 	}

// 	tknStr := c.Value
// 	status, claims, err := verifyJWT(tknStr)
// 	if err != nil {
// 		w.WriteHeader(status)
// 		return err
// 	}

// 	req := new(SendMessageReq)

// 	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
// 		return err
// 	}
// 	direct, err := s.store.GetDirectByID(req.DirectID)
// 	if err != nil {
// 		return err
// 	}
// 	if claims.ID != direct.FirstUser && claims.ID != direct.SecondUser {
// 		return fmt.Errorf("bad request")
// 	}
// 	message := NewMessage(claims.ID, direct.ID, req.Value)
// 	if err = s.store.CreateMessage(message); err != nil {
// 		return err
// 	}

// 	return nil
// }
