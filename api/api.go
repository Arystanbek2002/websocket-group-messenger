package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	errStatus "github.com/arystanbek2002/websocket-group-messenger/error_status"

	entity "github.com/arystanbek2002/websocket-group-messenger/messege_entities"
	"github.com/arystanbek2002/websocket-group-messenger/models"
	"github.com/arystanbek2002/websocket-group-messenger/storage"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

type APIServer struct {
	listenAddr string
	Store      storage.Storage
}

type APIError struct {
	Error string `json:"error"`
}

var (
	manager *entity.Manager
)

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		log.Println(v)
		return fmt.Errorf(errStatus.EncodeError)
	}
	return nil
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
		return fmt.Errorf(errStatus.EncodeError)
	}
	return nil
}

type APIFunc func(w http.ResponseWriter, r *http.Request, claims *Claims) error

func makeHTTPHandleFunc(f APIFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r, nil); err != nil {
			//actually status cant be changed as it set but to invoke the func status must be used as argument
			WriteJSON(w, http.StatusInternalServerError, APIError{Error: err.Error()})
		}
	}
}

func NewAPIServer(listenAddr string, store storage.Storage) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
		Store:      store,
	}
}

func (s *APIServer) Run() {
	err := godotenv.Load(".env")

	if err != nil {
		log.Printf("Error loading .env file")
	}

	ctx := context.Background()

	router := mux.NewRouter()
	manager = entity.NewManager(ctx, s.Store)

	router.Handle("/", ValidateJWT(http.FileServer(http.Dir("./static"))))
	router.Handle("/login.html", http.FileServer(http.Dir("./static")))
	router.Handle("/messenger.html", http.FileServer(http.Dir("./static")))
	router.HandleFunc("/direct", ValidateJWT2(s.handleGetDirects))
	router.Handle("/register.html", http.FileServer(http.Dir("./static")))
	router.HandleFunc("/registerUser", ValidateJWT2(s.handleCreateUser))
	router.HandleFunc("/ws", manager.ServeWC)
	router.HandleFunc("/loginUser", makeHTTPHandleFunc(s.handleLogin))
	router.HandleFunc("/loadMessenger", ValidateJWT2(s.loadMessenger))
	router.Handle("/user.html", ValidateJWT(http.FileServer(http.Dir("./static"))))
	router.HandleFunc("/getUsers", ValidateJWT2(s.handleGetUsers))
	router.HandleFunc("/user/{id}", ValidateJWT2(s.handleGetUser))
	router.HandleFunc("/message", ValidateJWT2(s.handleGetMessages))

	log.Println("Server running on port " + s.listenAddr)

	if err = http.ListenAndServe(s.listenAddr, router); err != nil {
		log.Printf("error starting server %s", err.Error())
	}
}

type Claims struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func generateJWT(user *models.User, t time.Time) (string, time.Time, error) {
	expirationTime := t.Add(10 * time.Minute)

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

func validateLoginRequest(req *models.UserRequest) (int, error) {
	if len(req.UserName) == 0 {
		return http.StatusBadRequest, fmt.Errorf(errStatus.WrongUsername)
	}
	if len(req.Password) == 0 {
		return http.StatusBadRequest, fmt.Errorf(errStatus.WrongPassword)
	}
	return http.StatusOK, nil
}

func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request, claims *Claims) error {

	req := new(models.UserRequest)

	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return WriteJSON(w, http.StatusBadRequest, APIError{Error: errStatus.JSONDecodingError})
	}

	status, err := validateLoginRequest(req)
	if err != nil {
		return WriteJSON(w, status, APIError{Error: errStatus.WrongCredentials})
	}

	user, err := s.Store.LoginUser(req.UserName, req.Password)
	if err != nil {
		if err.Error() == errStatus.WrongCredentials {
			return WriteJSON(w, http.StatusBadRequest, APIError{Error: err.Error()})
		}
		return WriteJSON(w, http.StatusInternalServerError, APIError{Error: errStatus.DBError})
	}

	jwToken, expirationTime, err := generateJWT(user, time.Now())
	if err != nil {
		return WriteJSON(w, http.StatusInternalServerError, APIError{Error: err.Error()})
	}

	userResp := new(models.UserResponce)
	userResp.ID = user.ID
	userResp.UserName = user.UserName
	userResp.Created_at = user.CreatedAt

	return WriteJSONlogin(w, http.StatusOK, userResp, jwToken, expirationTime)
}

func (s *APIServer) handleGetUsers(w http.ResponseWriter, r *http.Request, claims *Claims) error {

	type UsersResponce struct {
		Users []*models.UserResponce `json:"users"`
	}

	users, err := s.Store.GetUsers()
	if err != nil {
		return WriteJSON(w, http.StatusInternalServerError, APIError{Error: errStatus.DBError})
	}
	userResps := []*models.UserResponce{}
	for _, user := range users {
		if claims.ID == user.ID {
			continue
		}
		userResp := new(models.UserResponce)
		userResp.ID = user.ID
		userResp.UserName = user.UserName
		userResp.Created_at = user.CreatedAt
		userResps = append(userResps, userResp)
	}

	resp := new(UsersResponce)
	resp.Users = userResps
	return WriteJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleGetDirects(w http.ResponseWriter, r *http.Request, claims *Claims) error {
	directs, err := s.Store.GetDirects()
	if err != nil {
		return WriteJSON(w, http.StatusInternalServerError, APIError{Error: errStatus.DBError})
	}
	return WriteJSON(w, http.StatusOK, directs)
}

func (s *APIServer) handleGetMessages(w http.ResponseWriter, r *http.Request, claims *Claims) error {
	messages, err := s.Store.GetMessages()
	if err != nil {
		return WriteJSON(w, http.StatusInternalServerError, APIError{Error: errStatus.DBError})
	}
	return WriteJSON(w, http.StatusOK, messages)
}

func VerifyJWT(jwtString string) (int, *Claims, error) {
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(jwtString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		return http.StatusUnauthorized, nil, fmt.Errorf(errStatus.BadToken)
	}
	if !tkn.Valid {
		//theoretically should never reach it
		return http.StatusUnauthorized, nil, fmt.Errorf(errStatus.InvalidToken)
	}
	return http.StatusOK, claims, nil
}

func (s *APIServer) handleGetUser(w http.ResponseWriter, r *http.Request, claims *Claims) error {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, APIError{Error: errStatus.ParsingError})
	}

	user, err := s.Store.GetUser(id)
	if err != nil {
		if err.Error() == errStatus.UserNotFound {
			return WriteJSON(w, http.StatusBadRequest, APIError{Error: err.Error()})
		}
		return WriteJSON(w, http.StatusInternalServerError, APIError{Error: errStatus.DBError})
	}

	userResp := new(models.UserResponce)
	userResp.ID = user.ID
	userResp.UserName = user.UserName
	userResp.Created_at = user.CreatedAt

	return WriteJSON(w, http.StatusOK, userResp)
}

func (s *APIServer) handleCreateUser(w http.ResponseWriter, r *http.Request, claims *Claims) error {
	request := new(models.UserRequest)
	if err := json.NewDecoder(r.Body).Decode(request); err != nil {
		return WriteJSON(w, http.StatusBadRequest, APIError{Error: errStatus.JSONDecodingError})
	}
	status, err := validateLoginRequest(request)
	if err != nil {
		return WriteJSON(w, status, APIError{Error: errStatus.WrongCredentials})
	}
	user := models.NewUser(request.UserName, request.Password)

	if err := s.Store.CreateUser(user); err != nil {
		return WriteJSON(w, http.StatusInternalServerError, APIError{Error: errStatus.CreateUser})
	}

	return WriteJSON(w, http.StatusOK, "success")
}

func ValidateJWT(h http.Handler) http.Handler {
	return http.HandlerFunc(makeHTTPHandleFunc(func(w http.ResponseWriter, r *http.Request, claims *Claims) error {
		c, err := r.Cookie("x-jwt")
		if err != nil {
			return WriteJSON(w, http.StatusUnauthorized, APIError{Error: errStatus.NoCookie})
		}

		tknStr := c.Value
		status, _, err := VerifyJWT(tknStr)
		if err != nil {
			return WriteJSON(w, status, APIError{Error: err.Error()})
		}
		h.ServeHTTP(w, r)
		return nil
	}))
}

func (s *APIServer) loadMessenger(w http.ResponseWriter, r *http.Request, claims *Claims) error {
	type messengerRequest struct {
		SelectedUser int `json:"sel"`
	}
	req := new(messengerRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return WriteJSON(w, http.StatusBadRequest, APIError{Error: errStatus.JSONDecodingError})
	}
	direct_user, err := s.Store.GetUser(req.SelectedUser)
	if err != nil {
		if err.Error() == errStatus.UserNotFound {
			return WriteJSON(w, http.StatusBadRequest, APIError{Error: err.Error()})
		}
		return WriteJSON(w, http.StatusInternalServerError, APIError{Error: errStatus.DBError})
	}

	direct, err := s.Store.GetDirectByUsers(claims.ID, direct_user.ID)
	if err != nil {
		if err.Error() == errStatus.DirectNotFound {
			direct = models.NewDirect(claims.ID, direct_user.ID)
			err = s.Store.CreateDirect(direct)
			if err != nil {
				return WriteJSON(w, http.StatusInternalServerError, APIError{Error: errStatus.DBError})
			}
			direct, err = s.Store.GetDirectByUsers(claims.ID, direct_user.ID)
		}
		if err != nil {
			log.Println(err.Error())
			return WriteJSON(w, http.StatusInternalServerError, APIError{Error: errStatus.DBError})
		}
	}

	users := []*models.UserResponce{
		{
			ID:       claims.ID,
			UserName: claims.Username,
		},
		{
			ID:       direct_user.ID,
			UserName: direct_user.UserName,
		},
	}

	messages, err := s.Store.GetMessagesByDirect(direct.ID)
	if err != nil {
		return WriteJSON(w, http.StatusInternalServerError, APIError{Error: errStatus.DBError})
	}

	type messengerResponce struct {
		DirectID int                    `json:"direct_id"`
		Messages []*models.Message      `json:"messages"`
		Users    []*models.UserResponce `json:"users"`
	}

	resp := messengerResponce{
		DirectID: direct.ID,
		Messages: messages,
		Users:    users,
	}

	return WriteJSON(w, http.StatusOK, resp)
}

func ValidateJWT2(h APIFunc) http.HandlerFunc {
	return http.HandlerFunc(makeHTTPHandleFunc(func(w http.ResponseWriter, r *http.Request, v *Claims) error {
		c, err := r.Cookie("x-jwt")
		if err != nil {
			return WriteJSON(w, http.StatusUnauthorized, APIError{Error: errStatus.NoCookie})
		}

		tknStr := c.Value
		status, claims, err := VerifyJWT(tknStr)
		if err != nil {
			return WriteJSON(w, status, APIError{Error: err.Error()})
		}
		h(w, r, claims)
		return nil
	}))
}
