package api

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	stat "github.com/arystanbek2002/websocket-group-messenger/error_status"
	"github.com/arystanbek2002/websocket-group-messenger/models"
	mock "github.com/arystanbek2002/websocket-group-messenger/storage/mocks"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

func TestValidateLoginRequest(t *testing.T) {
	req := &models.UserRequest{
		UserName: "username",
		Password: "password",
	}
	status, err := validateLoginRequest(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
}

func TestValidateLoginRequestError(t *testing.T) {
	cases := []struct {
		name      string
		req       *models.UserRequest
		expError  error
		expStatus int
	}{
		{
			name:      "bad_username",
			req:       &models.UserRequest{UserName: ""},
			expError:  fmt.Errorf(stat.WrongUsername),
			expStatus: http.StatusBadRequest,
		},
		{
			name:      "bad_password",
			req:       &models.UserRequest{UserName: "username", Password: ""},
			expError:  fmt.Errorf(stat.WrongPassword),
			expStatus: http.StatusBadRequest,
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			status, err := validateLoginRequest(tCase.req)
			require.Error(t, err)
			require.EqualError(t, tCase.expError, err.Error())
			require.Equal(t, tCase.expStatus, status)
		})
	}
}

func TestHandleLogin(t *testing.T) {
	ctl := gomock.NewController(t)
	defer ctl.Finish()
	storage := mock.NewMockStorage(ctl)

	expUser := &models.User{
		ID:        1,
		UserName:  "test",
		Password:  "1234",
		CreatedAt: time.Date(2023, time.April, 14, 15, 16, 17, 18, time.UTC),
	}
	storage.EXPECT().LoginUser("test", "1234").Return(expUser, nil)

	api := NewAPIServer("8080:", storage)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodPost,
		"/loginUser",
		bytes.NewBuffer([]byte(
			[]byte(`{"username": "test", "password":"1234"}`),
		)),
	)
	req.Header.Set("Content-Type", "application/json")

	err := api.handleLogin(rec, req, nil)

	require.NoError(t, err)
	res := rec.Result()
	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
	require.NoError(t, err)
	expectedResp := `{"id":1,"username":"test","created_at":"2023-04-14T15:16:17.000000018Z"}` + "\n"
	require.Equal(t, expectedResp, string(data))
	expectedStatus := http.StatusOK
	require.Equal(t, expectedStatus, res.StatusCode)
	require.NotEmpty(t, res.Cookies())
}

func TestHandleLoginError(t *testing.T) {
	cases := []struct {
		name      string
		method    string
		data      *bytes.Buffer
		isMock    bool
		dbError   string
		expError  string
		expStatus int
	}{
		{
			name:   "badJSON",
			method: http.MethodPost,
			data: bytes.NewBuffer([]byte(
				[]byte(`{123, "1234"}`),
			)),
			isMock:    false,
			expError:  stat.JSONDecodingError,
			expStatus: http.StatusBadRequest,
		},
		{
			name:   "badRequest",
			method: http.MethodPost,
			data: bytes.NewBuffer([]byte(
				[]byte(`{"username": "", "password":"1234"}`),
			)),
			isMock:    false,
			expError:  stat.WrongCredentials,
			expStatus: http.StatusBadRequest,
		},
		{
			name:   "dbInternalError",
			method: http.MethodPost,
			data: bytes.NewBuffer([]byte(
				[]byte(`{"username": "test", "password":"1234"}`),
			)),
			isMock:    true,
			dbError:   "smth went wrong",
			expError:  stat.DBError,
			expStatus: http.StatusInternalServerError,
		},
		{
			name:   "dbError",
			method: http.MethodPost,
			data: bytes.NewBuffer([]byte(
				[]byte(`{"username": "test", "password":"1234"}`),
			)),
			isMock:    true,
			dbError:   stat.WrongCredentials,
			expError:  stat.WrongCredentials,
			expStatus: http.StatusBadRequest,
		},
	}

	ctl := gomock.NewController(t)
	defer ctl.Finish()
	storage := mock.NewMockStorage(ctl)

	api := NewAPIServer("8080:", storage)

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.isMock {
				storage.EXPECT().LoginUser("test", "1234").Return(nil, fmt.Errorf(tCase.dbError)).Times(1)
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(
				tCase.method,
				"/loginUser",
				tCase.data,
			)
			req.Header.Set("Content-Type", "application/json")
			err := api.handleLogin(rec, req, nil)
			require.NoError(t, err)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			expectedResp := `{"error":"` + tCase.expError + `"}` + "\n"
			require.Equal(t, expectedResp, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
			require.Empty(t, res.Cookies())
		})
	}

}

func TestWriteJSON(t *testing.T) {
	cases := []struct {
		name      string
		v         any
		status    int
		expStatus int
		expData   string
	}{
		{
			name:      "objectInt",
			v:         123,
			status:    http.StatusOK,
			expStatus: http.StatusOK,
			expData:   `123` + "\n",
		},
		{
			name:      "objectStr",
			v:         "test",
			status:    http.StatusOK,
			expStatus: http.StatusOK,
			expData:   `"test"` + "\n",
		},
		{
			name: "object",
			v: models.UserResponce{
				ID:         1,
				UserName:   "test",
				Created_at: time.Date(2023, time.April, 14, 15, 16, 17, 18, time.UTC),
			},
			status:    http.StatusOK,
			expStatus: http.StatusOK,
			expData:   `{"id":1,"username":"test","created_at":"2023-04-14T15:16:17.000000018Z"}` + "\n",
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			err := WriteJSON(rec, tCase.status, tCase.v)
			require.NoError(t, err)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			require.Equal(t, tCase.expData, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}

func TestWriteJSONError(t *testing.T) {
	cases := []struct {
		name      string
		v         any
		status    int
		expStatus int
		expData   string
		expError  string
	}{
		{
			name:      "objectChan",
			v:         make(chan int),
			status:    http.StatusOK,
			expStatus: http.StatusOK,
			expError:  stat.EncodeError,
		},
		{
			name:      "ObjectInf",
			v:         math.Inf(0),
			status:    http.StatusOK,
			expStatus: http.StatusOK,
			expError:  stat.EncodeError,
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			err := WriteJSON(rec, tCase.status, tCase.v)
			require.Error(t, err)
			require.EqualError(t, err, tCase.expError)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			require.Empty(t, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}

func TestWriteJSONlogin(t *testing.T) {
	cases := []struct {
		name      string
		v         any
		status    int
		jwt       string
		expTime   time.Time
		expStatus int
		expData   string
	}{
		{
			name:      "objectInt",
			v:         123,
			jwt:       "jwt-token",
			expTime:   time.Date(2053, time.April, 14, 15, 16, 17, 0, time.UTC),
			status:    http.StatusOK,
			expStatus: http.StatusOK,
			expData:   `123` + "\n",
		},
		{
			name:      "objectStr",
			v:         "test",
			jwt:       "jwt-token",
			expTime:   time.Date(2053, time.April, 14, 15, 16, 17, 0, time.UTC),
			status:    http.StatusOK,
			expStatus: http.StatusOK,
			expData:   `"test"` + "\n",
		},
		{
			name: "object",
			v: models.UserResponce{
				ID:         1,
				UserName:   "test",
				Created_at: time.Date(2023, time.April, 14, 15, 16, 17, 18, time.UTC),
			},
			jwt:       "jwt-token",
			expTime:   time.Date(2053, time.April, 14, 15, 16, 17, 0, time.UTC),
			status:    http.StatusOK,
			expStatus: http.StatusOK,
			expData:   `{"id":1,"username":"test","created_at":"2023-04-14T15:16:17.000000018Z"}` + "\n",
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			err := WriteJSONlogin(rec, tCase.status, tCase.v, tCase.jwt, tCase.expTime)
			require.NoError(t, err)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			require.Equal(t, tCase.expData, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)

			cookie := res.Cookies()[0]
			require.Equal(t, "x-jwt", cookie.Name)
			require.Equal(t, tCase.expTime, cookie.Expires)
			require.Equal(t, tCase.jwt, cookie.Value)
		})
	}
}

func TestWriteJSONloginError(t *testing.T) {
	cases := []struct {
		name      string
		v         any
		status    int
		expStatus int
		expTime   time.Time
		expData   string
		jwt       string
		expError  string
	}{
		{
			name:      "objectChan",
			v:         make(chan int),
			status:    http.StatusOK,
			expStatus: http.StatusOK,
			expTime:   time.Date(2053, time.April, 14, 15, 16, 17, 0, time.UTC),
			jwt:       "test",
			expError:  stat.EncodeError,
		},
		{
			name:      "ObjectInf",
			v:         math.Inf(0),
			status:    http.StatusOK,
			expStatus: http.StatusOK,
			expTime:   time.Date(2053, time.April, 14, 15, 16, 17, 0, time.UTC),
			jwt:       "test",
			expError:  stat.EncodeError,
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			err := WriteJSONlogin(rec, tCase.status, tCase.v, tCase.jwt, tCase.expTime)
			require.Error(t, err)
			require.EqualError(t, err, tCase.expError)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			require.Empty(t, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
			cookie := res.Cookies()[0]
			require.Equal(t, "x-jwt", cookie.Name)
			require.Equal(t, tCase.jwt, cookie.Value)
		})
	}
}

func TestGenerateJWT(t *testing.T) {
	cases := []struct {
		name    string
		time    time.Time
		user    *models.User
		expTime time.Time
		jwt     string
	}{
		{
			name: "firstJWT",
			time: time.Date(2050, time.August, 1, 14, 20, 28, 0, time.Local),
			user: &models.User{
				ID:        1,
				UserName:  "test",
				Password:  "1234",
				CreatedAt: time.Date(2022, time.April, 14, 15, 16, 17, 18, time.UTC),
			},
			expTime: time.Date(2050, time.August, 1, 14, 30, 28, 0, time.Local),
			jwt:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJ0ZXN0IiwiZXhwIjoyNTQyOTU1NDI4fQ.CdPd2qqBD0mz43n1j9bhEcm0_lm_Bn-59GKxTrLeoMQ",
		},
		{
			time: time.Date(2050, time.August, 1, 14, 37, 8, 0, time.Local),
			user: &models.User{
				ID:        2,
				UserName:  "test2",
				Password:  "1234",
				CreatedAt: time.Date(2022, time.April, 14, 15, 16, 17, 18, time.UTC),
			},
			expTime: time.Date(2050, time.August, 1, 14, 47, 8, 0, time.Local),
			jwt:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJ0ZXN0MiIsImV4cCI6MjU0Mjk1NjQyOH0.R71INip3PoEfWh3-Tr0MA2iO_XYXrrabeBZQw2eoptM",
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			jwt, time, err := generateJWT(tCase.user, tCase.time)
			require.NoError(t, err)
			require.Equal(t, tCase.jwt, jwt)
			require.Equal(t, tCase.expTime, time)
		})
	}
}

func TestVerifyJWT(t *testing.T) {
	type Claims struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
		jwt.RegisteredClaims
	}
	cases := []struct {
		name    string
		claims  *Claims
		status  int
		jwt     string
		expTime time.Time
	}{
		{
			name: "firstJWT",
			claims: &Claims{
				ID:       1,
				Username: "test",
			},
			status:  http.StatusOK,
			expTime: time.Date(2050, time.August, 1, 14, 30, 28, 0, time.Local),
			jwt:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJ0ZXN0IiwiZXhwIjoyNTQyOTU1NDI4fQ.CdPd2qqBD0mz43n1j9bhEcm0_lm_Bn-59GKxTrLeoMQ",
		},
		{
			name: "secondJWT",
			claims: &Claims{
				ID:       2,
				Username: "test2",
			},
			status:  http.StatusOK,
			expTime: time.Date(2050, time.August, 1, 14, 47, 8, 0, time.Local),
			jwt:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJ0ZXN0MiIsImV4cCI6MjU0Mjk1NjQyOH0.R71INip3PoEfWh3-Tr0MA2iO_XYXrrabeBZQw2eoptM",
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			status, claims, err := VerifyJWT(tCase.jwt)
			require.NoError(t, err)
			require.Equal(t, tCase.claims.ID, claims.ID)
			require.Equal(t, tCase.expTime, claims.ExpiresAt.Time)
			require.Equal(t, tCase.claims.Username, claims.Username)
			require.Equal(t, tCase.status, status)
		})
	}
}

func TestVerifyJWTError(t *testing.T) {

	cases := []struct {
		name     string
		status   int
		jwt      string
		expError string
	}{
		{
			name:     "badJWT",
			status:   http.StatusUnauthorized,
			jwt:      "eyJhbGciOiJIUzI1NiIsInR5cC3I6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJ0ZXN0IiwiZXhwIjoyNTQyOTU1NDI4fQ.CdPd2qqBD0mz43n1j9bhEcm0_lm_Bn-59GKxTrLeoMQ",
			expError: stat.BadToken,
		},
		{
			name:     "expiredJWT",
			status:   http.StatusUnauthorized,
			jwt:      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJ0ZXN0IiwiZXhwIjoxMDQyOTU1NDI4fQ.wRytjE0RaNYkVhye5j_RFvaT86jxrnib4uZx1ETHB9Q",
			expError: stat.BadToken,
		},
		{
			name:     "emptyJWT",
			status:   http.StatusUnauthorized,
			jwt:      "",
			expError: stat.BadToken,
		},
		{
			name:     "badFormat",
			status:   http.StatusUnauthorized,
			jwt:      "123",
			expError: stat.BadToken,
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			status, claims, err := VerifyJWT(tCase.jwt)
			require.Error(t, err)
			require.Empty(t, claims)
			require.Equal(t, tCase.expError, err.Error())
			require.Equal(t, tCase.status, status)
		})
	}
}

func TestMakeHTTPHandleFunc(t *testing.T) {

	cases := []struct {
		name      string
		expStatus int
		expData   string
		fun       APIFunc
	}{
		{
			name:      "func1",
			expStatus: http.StatusOK,
			expData:   `{"id":1,"username":"test","created_at":"2023-04-14T15:16:17.000000018Z"}` + "\n",
			fun: func(w http.ResponseWriter, r *http.Request, claims *Claims) error {
				return WriteJSON(w, http.StatusOK, &models.UserResponce{
					ID:         1,
					UserName:   "test",
					Created_at: time.Date(2023, time.April, 14, 15, 16, 17, 18, time.UTC),
				})
			},
		},
		{
			name: "func2",
			fun: func(w http.ResponseWriter, r *http.Request, claims *Claims) error {
				return nil
			},
			expStatus: http.StatusOK,
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", bytes.NewBuffer([]byte(
				[]byte(`{"id": 1}`),
			)))

			makeHTTPHandleFunc(tCase.fun)(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			require.Equal(t, tCase.expData, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}

}

func TestMakeHTTPHandleFuncError(t *testing.T) {

	cases := []struct {
		name      string
		expStatus int
		expError  string
		fun       APIFunc
	}{
		{
			name: "chanIntError",
			//status can't be overwritten so expecting original, anyway encoding fail scenario is not very likely to happen
			expStatus: http.StatusOK,

			expError: `{"error":"` + stat.EncodeError + `"}` + "\n",
			fun: func(w http.ResponseWriter, r *http.Request, claims *Claims) error {
				return WriteJSON(w, http.StatusOK, make(chan int))
			},
		},
		{
			name:     "maInfError",
			expError: `{"error":"` + stat.EncodeError + `"}` + "\n",
			fun: func(w http.ResponseWriter, r *http.Request, claims *Claims) error {
				return WriteJSON(w, http.StatusOK, math.Inf(0))
			},
			expStatus: http.StatusOK,
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", bytes.NewBuffer([]byte(
				[]byte(`{"id": 1}`),
			)))

			makeHTTPHandleFunc(tCase.fun)(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			require.Equal(t, tCase.expError, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}

}

func TestHandleCreateUser(t *testing.T) {

	cases := []struct {
		name      string
		method    string
		data      *bytes.Buffer
		expStatus int
	}{
		{
			name:   "goodSample1",
			method: http.MethodPost,
			data: bytes.NewBuffer([]byte(
				[]byte(`{"username": "test", "password":"1234"}`),
			)),
			expStatus: http.StatusOK,
		},
		{
			name:   "goodSample2",
			method: http.MethodPost,
			data: bytes.NewBuffer([]byte(
				[]byte(`{"username": "test1", "password":"1234"}`),
			)),
			expStatus: http.StatusOK,
		},
	}

	ctl := gomock.NewController(t)
	defer ctl.Finish()
	storage := mock.NewMockStorage(ctl)

	api := NewAPIServer("8080:", storage)

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {

			storage.EXPECT().CreateUser(gomock.Any()).Return(nil).Times(1)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(
				tCase.method,
				"/user",
				tCase.data,
			)
			req.Header.Set("Content-Type", "application/json")
			err := api.handleCreateUser(rec, req, nil)
			require.NoError(t, err)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			expectedResp := `"success"` + "\n"
			require.Equal(t, expectedResp, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}

func TestHandleCreateUserError(t *testing.T) {

	cases := []struct {
		name      string
		method    string
		data      *bytes.Buffer
		expError  string
		dbError   string
		isMock    bool
		expStatus int
	}{
		{
			name:   "badJSON",
			method: http.MethodPost,
			data: bytes.NewBuffer([]byte(
				[]byte(`{123, "1234"}`),
			)),
			isMock:    false,
			expError:  stat.JSONDecodingError,
			expStatus: http.StatusBadRequest,
		},
		{
			name:   "wrongFields",
			method: http.MethodPost,
			data: bytes.NewBuffer([]byte(
				[]byte(`{"123": "test", "qwe":"1234"}`),
			)),
			isMock:    false,
			expError:  stat.WrongCredentials,
			expStatus: http.StatusBadRequest,
		},
		{
			name:   "wrongFormat",
			method: http.MethodPost,
			data: bytes.NewBuffer([]byte(
				[]byte(`{"username": "test1"}`),
			)),
			isMock:    false,
			expError:  stat.WrongCredentials,
			expStatus: http.StatusBadRequest,
		},
		{
			name:   "dbError",
			method: http.MethodPost,
			data: bytes.NewBuffer([]byte(
				[]byte(`{"username": "test", "password":"1234"}`),
			)),
			isMock:    true,
			dbError:   "smth went wrong",
			expError:  stat.CreateUser,
			expStatus: http.StatusInternalServerError,
		},
	}

	ctl := gomock.NewController(t)
	defer ctl.Finish()
	storage := mock.NewMockStorage(ctl)

	api := NewAPIServer("8080:", storage)

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.isMock {
				storage.EXPECT().CreateUser(gomock.Any()).Return(fmt.Errorf(tCase.dbError)).Times(1)
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(
				tCase.method,
				"/user",
				tCase.data,
			)
			req.Header.Set("Content-Type", "application/json")
			err := api.handleCreateUser(rec, req, nil)
			require.NoError(t, err)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			expectedResp := `{"error":"` + tCase.expError + `"}` + "\n"
			require.Equal(t, expectedResp, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}

type Hand struct{}

func (h *Hand) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("success!"))
}

func TestValidateJWT(t *testing.T) {

	cases := []struct {
		name      string
		method    string
		isCookie  bool
		cookie    string
		expStatus int
		expTime   time.Time
		handler   http.Handler
	}{
		{
			name:      "goodSample1",
			method:    http.MethodGet,
			expStatus: http.StatusOK,
			isCookie:  true,
			expTime:   time.Date(2050, time.August, 1, 14, 30, 28, 0, time.Local),
			cookie:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJ0ZXN0IiwiZXhwIjoyNTQyOTU1NDI4fQ.CdPd2qqBD0mz43n1j9bhEcm0_lm_Bn-59GKxTrLeoMQ",

			handler: &Hand{},
		},
		{
			name:      "goodSample2",
			method:    http.MethodGet,
			expStatus: http.StatusOK,
			isCookie:  true,
			expTime:   time.Date(2050, time.August, 1, 14, 47, 8, 0, time.Local),
			cookie:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJ0ZXN0MiIsImV4cCI6MjU0Mjk1NjQyOH0.R71INip3PoEfWh3-Tr0MA2iO_XYXrrabeBZQw2eoptM",

			handler: &Hand{},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			req := httptest.NewRequest(
				tCase.method,
				"/direct",
				bytes.NewBuffer([]byte(
					[]byte(``),
				)),
			)
			if tCase.isCookie {
				cookie := &http.Cookie{Name: "x-jwt", Value: tCase.cookie,
					Expires: tCase.expTime}
				req.AddCookie(cookie)
			}

			rec := httptest.NewRecorder()

			req.Header.Set("Content-Type", "application/json")
			handler := ValidateJWT(tCase.handler)
			handler.ServeHTTP(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			require.Equal(t, "success!", string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}

func TestValidateJWTError(t *testing.T) {

	cases := []struct {
		name      string
		method    string
		isCookie  bool
		cookie    string
		expStatus int
		expError  string
		handler   http.Handler
	}{
		{
			name:      "noJWT",
			method:    http.MethodGet,
			expStatus: http.StatusUnauthorized,
			isCookie:  false,
			expError:  stat.NoCookie,
			handler:   &Hand{},
		},
		{
			name:      "badJWT",
			method:    http.MethodGet,
			expStatus: http.StatusUnauthorized,
			isCookie:  true,
			expError:  stat.BadToken,
			cookie:    "eyJhbGciOiJIUz!ZXC!I1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJ0ZXN0MiIsImV4cCI6MjU0Mjk1NjQyOH0.R71INip3PoEfWh3-Tr0MA2iO_XYXrrabeBZQw2eoptM",
			handler:   &Hand{},
		},
		{
			name:      "expiredJWT",
			method:    http.MethodGet,
			expStatus: http.StatusUnauthorized,
			isCookie:  true,
			expError:  stat.BadToken,
			cookie:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJ0ZXN0IiwiZXhwIjoxMDQyOTU1NDI4fQ.wRytjE0RaNYkVhye5j_RFvaT86jxrnib4uZx1ETHB9Q",
			handler:   &Hand{},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			req := httptest.NewRequest(
				tCase.method,
				"/direct",
				bytes.NewBuffer([]byte(
					[]byte(``),
				)),
			)
			if tCase.isCookie {
				cookie := &http.Cookie{Name: "x-jwt", Value: tCase.cookie,
					Expires: time.Date(2050, time.August, 1, 14, 47, 8, 0, time.Local)}
				req.AddCookie(cookie)
			}
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			handler := ValidateJWT(tCase.handler)
			handler.ServeHTTP(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			expectedResp := `{"error":"` + tCase.expError + `"}` + "\n"
			require.Equal(t, expectedResp, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}

func TestHandleGetDirects(t *testing.T) {

	cases := []struct {
		name      string
		method    string
		data      []*models.Direct
		expData   string
		expStatus int
	}{
		{
			name:      "goodSample1",
			method:    http.MethodGet,
			expStatus: http.StatusOK,
			data: []*models.Direct{
				{
					ID:         1,
					FirstUser:  3,
					SecondUser: 4,
					CreatedAt:  time.Date(2053, time.April, 14, 15, 16, 17, 0, time.UTC),
				},
				{
					ID:         2,
					FirstUser:  1,
					SecondUser: 2,
					CreatedAt:  time.Date(2033, time.April, 14, 15, 16, 17, 0, time.UTC),
				},
			},
			expData: `[{"id":1,"first_user":3,"second_user":4,"created_at":"2053-04-14T15:16:17Z"},{"id":2,"first_user":1,"second_user":2,"created_at":"2033-04-14T15:16:17Z"}]` + "\n",
		},
		{
			name:      "goodSample2",
			method:    http.MethodGet,
			expStatus: http.StatusOK,
			data: []*models.Direct{
				{
					ID:         4,
					FirstUser:  12,
					SecondUser: 14,
					CreatedAt:  time.Date(2023, time.April, 14, 15, 16, 17, 0, time.UTC),
				},
				{
					ID:         6,
					FirstUser:  31,
					SecondUser: 42,
					CreatedAt:  time.Date(2013, time.April, 14, 15, 16, 17, 0, time.UTC),
				},
			},
			expData: `[{"id":4,"first_user":12,"second_user":14,"created_at":"2023-04-14T15:16:17Z"},{"id":6,"first_user":31,"second_user":42,"created_at":"2013-04-14T15:16:17Z"}]` + "\n",
		},
	}

	ctl := gomock.NewController(t)
	defer ctl.Finish()
	storage := mock.NewMockStorage(ctl)

	api := NewAPIServer("8080:", storage)

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {

			storage.EXPECT().GetDirects().Return(tCase.data, nil).Times(1)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(
				tCase.method,
				"/direct",
				bytes.NewBuffer([]byte(
					[]byte(``),
				)),
			)

			req.Header.Set("Content-Type", "application/json")
			err := api.handleGetDirects(rec, req, nil)
			require.NoError(t, err)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			expectedResp := tCase.expData
			require.Equal(t, expectedResp, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}
func TestHandleGetDirectsError(t *testing.T) {

	cases := []struct {
		name      string
		method    string
		dbError   string
		expData   string
		expStatus int
	}{
		{
			name:      "dbError1",
			method:    http.MethodGet,
			expStatus: http.StatusInternalServerError,
			dbError:   "smth went wrong",
			expData:   stat.DBError,
		},
		{
			name:      "dbError2",
			method:    http.MethodGet,
			expStatus: http.StatusInternalServerError,
			dbError:   "db is down",
			expData:   stat.DBError,
		},
	}

	ctl := gomock.NewController(t)
	defer ctl.Finish()
	storage := mock.NewMockStorage(ctl)

	api := NewAPIServer("8080:", storage)

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {

			storage.EXPECT().GetDirects().Return(nil, fmt.Errorf(tCase.dbError)).Times(1)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(
				tCase.method,
				"/direct",
				bytes.NewBuffer([]byte(
					[]byte(``),
				)),
			)

			req.Header.Set("Content-Type", "application/json")
			err := api.handleGetDirects(rec, req, nil)
			require.NoError(t, err)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			expectedResp := `{"error":"` + tCase.expData + `"}` + "\n"
			require.Equal(t, expectedResp, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}

func TestValidateJWT2(t *testing.T) {
	cases := []struct {
		name      string
		method    string
		isCookie  bool
		cookie    string
		expStatus int
		expValue  string
		expTime   time.Time
		fun       APIFunc
	}{
		{
			name:      "goodSample1",
			method:    http.MethodGet,
			expStatus: http.StatusOK,
			expValue:  `"success!"` + "\n",
			isCookie:  true,
			expTime:   time.Date(2050, time.August, 1, 14, 30, 28, 0, time.Local),
			cookie:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJ0ZXN0IiwiZXhwIjoyNTQyOTU1NDI4fQ.CdPd2qqBD0mz43n1j9bhEcm0_lm_Bn-59GKxTrLeoMQ",
			fun: func(w http.ResponseWriter, r *http.Request, claims *Claims) error {
				return WriteJSON(w, 200, "success!")
			},
		},
		{
			name:      "goodSample2",
			method:    http.MethodGet,
			expStatus: http.StatusOK,
			expValue:  `"success!"` + "\n",
			isCookie:  true,
			expTime:   time.Date(2050, time.August, 1, 14, 47, 8, 0, time.Local),
			cookie:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJ0ZXN0MiIsImV4cCI6MjU0Mjk1NjQyOH0.R71INip3PoEfWh3-Tr0MA2iO_XYXrrabeBZQw2eoptM",
			fun: func(w http.ResponseWriter, r *http.Request, claims *Claims) error {
				return WriteJSON(w, 200, "success!")
			},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			req := httptest.NewRequest(
				tCase.method,
				"/direct",
				bytes.NewBuffer([]byte(
					[]byte(``),
				)),
			)
			if tCase.isCookie {
				cookie := &http.Cookie{Name: "x-jwt", Value: tCase.cookie,
					Expires: tCase.expTime}
				req.AddCookie(cookie)
			}

			rec := httptest.NewRecorder()

			req.Header.Set("Content-Type", "application/json")
			handlerFunc := ValidateJWT2(tCase.fun)
			handlerFunc(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			require.Equal(t, tCase.expValue, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}

func TestValidateJWT2Error(t *testing.T) {

	cases := []struct {
		name      string
		method    string
		isCookie  bool
		cookie    string
		expStatus int
		expError  string
		fun       APIFunc
	}{
		{
			name:      "noJWT",
			method:    http.MethodGet,
			expStatus: http.StatusUnauthorized,
			isCookie:  false,
			expError:  stat.NoCookie,
			fun: func(w http.ResponseWriter, r *http.Request, claims *Claims) error {
				return WriteJSON(w, 200, "success!")
			},
		},
		{
			name:      "badJWT",
			method:    http.MethodGet,
			expStatus: http.StatusUnauthorized,
			isCookie:  true,
			expError:  stat.BadToken,
			cookie:    "eyJhbGciOiJIUz!ZXC!I1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJ0ZXN0MiIsImV4cCI6MjU0Mjk1NjQyOH0.R71INip3PoEfWh3-Tr0MA2iO_XYXrrabeBZQw2eoptM",
			fun: func(w http.ResponseWriter, r *http.Request, claims *Claims) error {
				return WriteJSON(w, 200, "success!")
			},
		},
		{
			name:      "expiredJWT",
			method:    http.MethodGet,
			expStatus: http.StatusUnauthorized,
			isCookie:  true,
			expError:  stat.BadToken,
			cookie:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJ0ZXN0IiwiZXhwIjoxMDQyOTU1NDI4fQ.wRytjE0RaNYkVhye5j_RFvaT86jxrnib4uZx1ETHB9Q",
			fun: func(w http.ResponseWriter, r *http.Request, claims *Claims) error {
				return WriteJSON(w, 200, "success!")
			},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			req := httptest.NewRequest(
				tCase.method,
				"/direct",
				bytes.NewBuffer([]byte(
					[]byte(``),
				)),
			)
			if tCase.isCookie {
				cookie := &http.Cookie{Name: "x-jwt", Value: tCase.cookie,
					Expires: time.Date(2050, time.August, 1, 14, 47, 8, 0, time.Local)}
				req.AddCookie(cookie)
			}
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			handlerFunc := ValidateJWT2(tCase.fun)
			handlerFunc(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			expectedResp := `{"error":"` + tCase.expError + `"}` + "\n"
			require.Equal(t, expectedResp, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}

func TestHandleGetUsers(t *testing.T) {

	cases := []struct {
		name      string
		method    string
		data      []*models.User
		expData   string
		expStatus int
		claims    *Claims
	}{
		{
			name:      "goodSample1",
			method:    http.MethodGet,
			expStatus: http.StatusOK,
			data: []*models.User{
				{
					ID:        1,
					UserName:  "test1",
					Password:  "123",
					CreatedAt: time.Date(2053, time.April, 14, 15, 16, 17, 0, time.UTC),
				},
				{
					ID:        2,
					UserName:  "test2",
					Password:  "123",
					CreatedAt: time.Date(2033, time.April, 14, 15, 16, 17, 0, time.UTC),
				},
			},
			expData: `{"users":[{"id":1,"username":"test1","created_at":"2053-04-14T15:16:17Z"},{"id":2,"username":"test2","created_at":"2033-04-14T15:16:17Z"}]}` + "\n",
			claims: &Claims{
				ID:       3,
				Username: "test4",
			},
		},
		{
			name:      "goodSample2",
			method:    http.MethodGet,
			expStatus: http.StatusOK,
			data: []*models.User{
				{
					ID:        3,
					UserName:  "test3",
					Password:  "123",
					CreatedAt: time.Date(2033, time.April, 14, 15, 16, 17, 0, time.UTC),
				},
				{
					ID:        4,
					UserName:  "test4",
					Password:  "123",
					CreatedAt: time.Date(2043, time.April, 14, 15, 16, 17, 0, time.UTC),
				},
			},
			expData: `{"users":[{"id":4,"username":"test4","created_at":"2043-04-14T15:16:17Z"}]}` + "\n",
			claims: &Claims{
				ID:       3,
				Username: "test3",
			},
		},
	}

	ctl := gomock.NewController(t)
	defer ctl.Finish()
	storage := mock.NewMockStorage(ctl)

	api := NewAPIServer("8080:", storage)

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {

			storage.EXPECT().GetUsers().Return(tCase.data, nil).Times(1)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(
				tCase.method,
				"/getUser",
				bytes.NewBuffer([]byte(
					[]byte(``),
				)),
			)

			req.Header.Set("Content-Type", "application/json")
			err := api.handleGetUsers(rec, req, tCase.claims)
			require.NoError(t, err)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			expectedResp := tCase.expData
			require.Equal(t, expectedResp, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}
func TestHandleGetUsersError(t *testing.T) {

	cases := []struct {
		name      string
		method    string
		dbError   string
		expData   string
		expStatus int
		claims    *Claims
	}{
		{
			name:      "dbError1",
			method:    http.MethodGet,
			expStatus: http.StatusInternalServerError,
			dbError:   "smth went wrong",
			expData:   stat.DBError,
			claims: &Claims{
				ID:       3,
				Username: "test4",
			},
		},
		{
			name:      "dbError2",
			method:    http.MethodGet,
			expStatus: http.StatusInternalServerError,
			dbError:   "db is down",
			expData:   stat.DBError,
			claims: &Claims{
				ID:       3,
				Username: "test4",
			},
		},
	}

	ctl := gomock.NewController(t)
	defer ctl.Finish()
	storage := mock.NewMockStorage(ctl)

	api := NewAPIServer("8080:", storage)

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {

			storage.EXPECT().GetUsers().Return(nil, fmt.Errorf(tCase.dbError)).Times(1)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(
				tCase.method,
				"/user",
				bytes.NewBuffer([]byte(
					[]byte(``),
				)),
			)

			req.Header.Set("Content-Type", "application/json")
			err := api.handleGetUsers(rec, req, tCase.claims)
			require.NoError(t, err)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			expectedResp := `{"error":"` + tCase.expData + `"}` + "\n"
			require.Equal(t, expectedResp, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}

func TestHandleGetMessages(t *testing.T) {
	cases := []struct {
		name      string
		method    string
		data      []*models.Message
		expData   string
		expStatus int
	}{
		{
			name:      "goodSample1",
			method:    http.MethodGet,
			expStatus: http.StatusOK,
			data: []*models.Message{
				{
					ID:        1,
					From:      1,
					DirectID:  1,
					Value:     "test1",
					CreatedAt: time.Date(2013, time.April, 14, 15, 16, 17, 0, time.UTC),
				},
				{
					ID:        2,
					From:      2,
					DirectID:  2,
					Value:     "test2",
					CreatedAt: time.Date(2023, time.April, 14, 15, 16, 17, 0, time.UTC),
				},
			},
			expData: `[{"id":1,"from":1,"direct_id":1,"value":"test1","created_at":"2013-04-14T15:16:17Z"},{"id":2,"from":2,"direct_id":2,"value":"test2","created_at":"2023-04-14T15:16:17Z"}]` + "\n",
		},
		{
			name:      "goodSample2",
			method:    http.MethodGet,
			expStatus: http.StatusOK,
			data: []*models.Message{
				{
					ID:        3,
					From:      3,
					DirectID:  3,
					Value:     "test3",
					CreatedAt: time.Date(2033, time.April, 14, 15, 16, 17, 0, time.UTC),
				},
				{
					ID:        4,
					From:      4,
					DirectID:  4,
					Value:     "test4",
					CreatedAt: time.Date(2043, time.April, 14, 15, 16, 17, 0, time.UTC),
				},
			},
			expData: `[{"id":3,"from":3,"direct_id":3,"value":"test3","created_at":"2033-04-14T15:16:17Z"},{"id":4,"from":4,"direct_id":4,"value":"test4","created_at":"2043-04-14T15:16:17Z"}]` + "\n",
		},
	}

	ctl := gomock.NewController(t)
	defer ctl.Finish()
	storage := mock.NewMockStorage(ctl)

	api := NewAPIServer("8080:", storage)

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {

			storage.EXPECT().GetMessages().Return(tCase.data, nil).Times(1)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(
				tCase.method,
				"/messages",
				bytes.NewBuffer([]byte(
					[]byte(``),
				)),
			)

			req.Header.Set("Content-Type", "application/json")
			err := api.handleGetMessages(rec, req, nil)
			require.NoError(t, err)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			expectedResp := tCase.expData
			require.Equal(t, expectedResp, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}
func TestHandleGetMessagesError(t *testing.T) {

	cases := []struct {
		name      string
		method    string
		dbError   string
		expData   string
		expStatus int
	}{
		{
			name:      "dbError1",
			method:    http.MethodGet,
			expStatus: http.StatusInternalServerError,
			dbError:   "smth went wrong",
			expData:   stat.DBError,
		},
		{
			name:      "dbError2",
			method:    http.MethodGet,
			expStatus: http.StatusInternalServerError,
			dbError:   "db is down",
			expData:   stat.DBError,
		},
	}

	ctl := gomock.NewController(t)
	defer ctl.Finish()
	storage := mock.NewMockStorage(ctl)

	api := NewAPIServer("8080:", storage)

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {

			storage.EXPECT().GetMessages().Return(nil, fmt.Errorf(tCase.dbError)).Times(1)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(
				tCase.method,
				"/messages",
				bytes.NewBuffer([]byte(
					[]byte(``),
				)),
			)

			req.Header.Set("Content-Type", "application/json")
			err := api.handleGetMessages(rec, req, nil)
			require.NoError(t, err)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			expectedResp := `{"error":"` + tCase.expData + `"}` + "\n"
			require.Equal(t, expectedResp, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}

func TestHandleGetUser(t *testing.T) {
	cases := []struct {
		name      string
		method    string
		data      *models.User
		expData   string
		id        string
		ID        int
		expStatus int
	}{
		{
			name:      "goodSample1",
			method:    http.MethodGet,
			expStatus: http.StatusOK,
			id:        "1",
			ID:        1,
			data: &models.User{
				ID:        1,
				UserName:  "test1",
				Password:  "123",
				CreatedAt: time.Date(2013, time.April, 14, 15, 16, 17, 0, time.UTC),
			},
			expData: `{"id":1,"username":"test1","created_at":"2013-04-14T15:16:17Z"}` + "\n",
		},
		{
			name:      "goodSample2",
			method:    http.MethodGet,
			expStatus: http.StatusOK,
			id:        "2",
			ID:        2,
			data: &models.User{
				ID:        2,
				UserName:  "test2",
				Password:  "123",
				CreatedAt: time.Date(2023, time.April, 14, 15, 16, 17, 0, time.UTC),
			},
			expData: `{"id":2,"username":"test2","created_at":"2023-04-14T15:16:17Z"}` + "\n",
		},
	}
	ctl := gomock.NewController(t)
	defer ctl.Finish()
	storage := mock.NewMockStorage(ctl)

	api := NewAPIServer("8080:", storage)

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			storage.EXPECT().GetUser(tCase.ID).Return(tCase.data, nil).Times(1)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(
				tCase.method,
				"/user/"+tCase.id,
				bytes.NewBuffer([]byte(
					[]byte(``),
				)),
			)

			router := mux.NewRouter()
			router.HandleFunc("/user/{id}", makeHTTPHandleFunc(api.handleGetUser))
			router.ServeHTTP(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			require.Equal(t, tCase.expData, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}

func TestHandleGetUserError(t *testing.T) {
	cases := []struct {
		name      string
		method    string
		isMock    bool
		dbError   error
		expData   string
		id        string
		ID        int
		expStatus int
	}{
		{
			name:      "parsingErr1",
			method:    http.MethodGet,
			expStatus: http.StatusBadRequest,
			id:        "1x",
			ID:        0,
			isMock:    false,
			expData:   stat.ParsingError,
		},
		{
			name:      "parsingErr2",
			method:    http.MethodGet,
			expStatus: http.StatusBadRequest,
			id:        "asd",
			ID:        0,
			isMock:    false,
			expData:   stat.ParsingError,
		},
		{
			name:      "userNotFoundErr",
			method:    http.MethodGet,
			expStatus: http.StatusBadRequest,
			id:        "123",
			ID:        123,
			isMock:    true,
			dbError:   fmt.Errorf(stat.UserNotFound),
			expData:   stat.UserNotFound,
		},
		{
			name:      "dbError",
			method:    http.MethodGet,
			expStatus: http.StatusInternalServerError,
			id:        "2",
			ID:        2,
			isMock:    true,
			dbError:   fmt.Errorf("smth went wrong"),
			expData:   stat.DBError,
		},
	}
	ctl := gomock.NewController(t)
	defer ctl.Finish()
	storage := mock.NewMockStorage(ctl)

	api := NewAPIServer("8080:", storage)

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.isMock {
				storage.EXPECT().GetUser(tCase.ID).Return(nil, tCase.dbError).Times(1)
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(
				tCase.method,
				"/user/"+tCase.id,
				bytes.NewBuffer([]byte(
					[]byte(``),
				)),
			)

			router := mux.NewRouter()
			router.HandleFunc("/user/{id}", makeHTTPHandleFunc(api.handleGetUser))
			router.ServeHTTP(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			expectedResp := `{"error":"` + tCase.expData + `"}` + "\n"
			require.Equal(t, expectedResp, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}

func TestLoadMessenger(t *testing.T) {
	cases := []struct {
		name              string
		method            string
		selUserID         int
		userData          *models.User
		directByUsersData *models.Direct
		messagesData      []*models.Message
		claims            *Claims
		isExists          bool
		expData           string
		expStatus         int
	}{
		{
			name:      "exists",
			method:    http.MethodPost,
			expStatus: http.StatusOK,
			selUserID: 2,
			userData: &models.User{
				ID:        2,
				UserName:  "test2",
				CreatedAt: time.Now(),
			},
			directByUsersData: &models.Direct{
				ID:         1,
				FirstUser:  1,
				SecondUser: 2,
				CreatedAt:  time.Now(),
			},
			messagesData: []*models.Message{
				{
					ID:        1,
					From:      2,
					DirectID:  1,
					Value:     "test-mess1",
					CreatedAt: time.Date(2033, time.April, 14, 15, 16, 17, 0, time.UTC),
				},
				{
					ID:        2,
					From:      1,
					DirectID:  1,
					Value:     "test-mess2",
					CreatedAt: time.Date(2043, time.April, 14, 15, 16, 17, 0, time.UTC),
				},
			},
			claims: &Claims{
				ID:       1,
				Username: "test1",
			},
			isExists: true,
			expData:  `{"direct_id":1,"messages":[{"id":1,"from":2,"direct_id":1,"value":"test-mess1","created_at":"2033-04-14T15:16:17Z"},{"id":2,"from":1,"direct_id":1,"value":"test-mess2","created_at":"2043-04-14T15:16:17Z"}],"users":[{"id":1,"username":"test1","created_at":"0001-01-01T00:00:00Z"},{"id":2,"username":"test2","created_at":"0001-01-01T00:00:00Z"}]}` + "\n",
		},
		{
			name:      "notExists",
			method:    http.MethodPost,
			expStatus: http.StatusOK,
			selUserID: 2,
			userData: &models.User{
				ID:        2,
				UserName:  "test2",
				CreatedAt: time.Now(),
			},
			directByUsersData: &models.Direct{
				ID:         1,
				FirstUser:  1,
				SecondUser: 2,
				CreatedAt:  time.Now(),
			},
			messagesData: []*models.Message{},
			claims: &Claims{
				ID:       1,
				Username: "test1",
			},
			isExists: false,
			expData:  `{"direct_id":1,"messages":[],"users":[{"id":1,"username":"test1","created_at":"0001-01-01T00:00:00Z"},{"id":2,"username":"test2","created_at":"0001-01-01T00:00:00Z"}]}` + "\n",
		},
	}

	ctl := gomock.NewController(t)
	defer ctl.Finish()
	storage := mock.NewMockStorage(ctl)

	api := NewAPIServer("8080:", storage)

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			storage.EXPECT().GetUser(tCase.selUserID).Return(tCase.userData, nil).Times(1)

			if tCase.isExists {
				storage.EXPECT().GetDirectByUsers(tCase.claims.ID, tCase.userData.ID).Return(tCase.directByUsersData, nil).Times(1)
			} else {
				storage.EXPECT().GetDirectByUsers(tCase.claims.ID, tCase.userData.ID).Return(nil, fmt.Errorf(stat.DirectNotFound)).Times(1)
				storage.EXPECT().CreateDirect(gomock.Any()).Return(nil).Times(1)
				storage.EXPECT().GetDirectByUsers(tCase.claims.ID, tCase.userData.ID).Return(tCase.directByUsersData, nil).Times(1)
			}

			storage.EXPECT().GetMessagesByDirect(tCase.directByUsersData.ID).Return(tCase.messagesData, nil).Times(1)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(
				tCase.method,
				"/loadMessenger",
				bytes.NewBuffer([]byte(
					[]byte(`{"sel": `+strconv.Itoa(tCase.userData.ID)+`}`),
				)),
			)

			err := api.loadMessenger(rec, req, tCase.claims)
			require.NoError(t, err)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			require.Equal(t, tCase.expData, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}

func TestLoadMessengerError(t *testing.T) {
	type mockValues struct {
		data any
		err  error
	}

	cases := []struct {
		name             string
		method           string
		reqData          string
		selUserID        int
		directID         int
		mocks            []int
		userData         mockValues
		directData       mockValues
		directData2      mockValues
		createDirectData mockValues
		messagesData     mockValues
		claims           *Claims
		expData          string
		expStatus        int
	}{
		{
			name:      "decodingError",
			method:    http.MethodPost,
			expStatus: http.StatusBadRequest,
			reqData:   `{sel:"12}`,
			expData:   stat.JSONDecodingError,
			mocks:     []int{0, 0, 0, 0, 0},
		},
		{
			name:      "userNotFoundError",
			method:    http.MethodPost,
			expStatus: http.StatusBadRequest,
			selUserID: 2,
			reqData:   `{"sel":2}`,
			userData: mockValues{
				data: nil,
				err:  fmt.Errorf(stat.UserNotFound),
			},
			expData: stat.UserNotFound,
			mocks:   []int{1, 0, 0, 0, 0},
		},
		{
			name:      "internalDBUserError",
			method:    http.MethodPost,
			expStatus: http.StatusInternalServerError,
			selUserID: 2,
			reqData:   `{"sel":2}`,
			userData: mockValues{
				data: nil,
				err:  fmt.Errorf("smth went wrong"),
			},
			expData: stat.DBError,
			mocks:   []int{1, 0, 0, 0, 0},
		},
		{
			name:      "internalDBDirectError",
			method:    http.MethodPost,
			expStatus: http.StatusInternalServerError,
			selUserID: 2,
			reqData:   `{"sel":2}`,
			userData: mockValues{
				data: &models.User{
					ID:        2,
					UserName:  "test2",
					CreatedAt: time.Now(),
				},
				err: nil,
			},
			directData: mockValues{
				data: nil,
				err:  fmt.Errorf("smth went wrong"),
			},
			expData: stat.DBError,
			mocks:   []int{1, 1, 0, 0, 0},
			claims: &Claims{
				ID:       1,
				Username: "test1",
			},
		},
		{
			name:      "createDirectError",
			method:    http.MethodPost,
			expStatus: http.StatusInternalServerError,
			selUserID: 2,
			reqData:   `{"sel":2}`,
			userData: mockValues{
				data: &models.User{
					ID:        2,
					UserName:  "test2",
					CreatedAt: time.Now(),
				},
				err: nil,
			},
			directData: mockValues{
				data: nil,
				err:  fmt.Errorf(stat.DirectNotFound),
			},
			createDirectData: mockValues{
				err: fmt.Errorf("smth went wrong"),
			},
			expData: stat.DBError,
			mocks:   []int{1, 1, 1, 0, 0},
			claims: &Claims{
				ID:       1,
				Username: "test1",
			},
		},
		{
			name:      "internalDBDirectError2",
			method:    http.MethodPost,
			expStatus: http.StatusInternalServerError,
			selUserID: 2,
			reqData:   `{"sel":2}`,
			userData: mockValues{
				data: &models.User{
					ID:        2,
					UserName:  "test2",
					CreatedAt: time.Now(),
				},
				err: nil,
			},
			directData: mockValues{
				data: nil,
				err:  fmt.Errorf(stat.DirectNotFound),
			},
			createDirectData: mockValues{
				err: nil,
			},
			directData2: mockValues{
				data: nil,
				err:  fmt.Errorf("smth went wrong"),
			},
			expData: stat.DBError,
			mocks:   []int{1, 1, 1, 1, 0},
			claims: &Claims{
				ID:       1,
				Username: "test1",
			},
		},
		{
			name:      "messagesError",
			method:    http.MethodPost,
			expStatus: http.StatusInternalServerError,
			selUserID: 2,
			reqData:   `{"sel":2}`,
			userData: mockValues{
				data: &models.User{
					ID:        2,
					UserName:  "test2",
					CreatedAt: time.Now(),
				},
				err: nil,
			},
			directData: mockValues{
				data: nil,
				err:  fmt.Errorf(stat.DirectNotFound),
			},
			createDirectData: mockValues{
				err: nil,
			},
			directID: 1,
			directData2: mockValues{
				data: &models.Direct{
					ID:         1,
					FirstUser:  1,
					SecondUser: 2,
					CreatedAt:  time.Now(),
				},
				err: nil,
			},
			messagesData: mockValues{
				data: nil,
				err:  fmt.Errorf("smth went wrong"),
			},
			expData: stat.DBError,
			mocks:   []int{1, 1, 1, 1, 1},
			claims: &Claims{
				ID:       1,
				Username: "test1",
			},
		},
		{
			name:      "messagesError2",
			method:    http.MethodPost,
			expStatus: http.StatusInternalServerError,
			selUserID: 2,
			reqData:   `{"sel":2}`,
			userData: mockValues{
				data: &models.User{
					ID:        2,
					UserName:  "test2",
					CreatedAt: time.Now(),
				},
				err: nil,
			},
			directID: 1,
			directData: mockValues{
				data: &models.Direct{
					ID:         1,
					FirstUser:  1,
					SecondUser: 2,
					CreatedAt:  time.Now(),
				},
				err: nil,
			},
			messagesData: mockValues{
				data: nil,
				err:  fmt.Errorf("smth went wrong"),
			},
			expData: stat.DBError,
			mocks:   []int{1, 1, 0, 0, 1},
			claims: &Claims{
				ID:       1,
				Username: "test1",
			},
		},
	}

	ctl := gomock.NewController(t)
	defer ctl.Finish()
	storage := mock.NewMockStorage(ctl)

	api := NewAPIServer("8080:", storage)

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.mocks[0] != 0 {
				storage.EXPECT().GetUser(tCase.selUserID).Return(tCase.userData.data, tCase.userData.err).Times(1)
			}
			if tCase.mocks[1] != 0 {
				storage.EXPECT().GetDirectByUsers(tCase.claims.ID, tCase.selUserID).Return(tCase.directData.data, tCase.directData.err).Times(1)
			}
			if tCase.mocks[2] != 0 {
				storage.EXPECT().CreateDirect(gomock.Any()).Return(tCase.createDirectData.err).Times(1)

			}
			if tCase.mocks[3] != 0 {
				storage.EXPECT().GetDirectByUsers(tCase.claims.ID, tCase.selUserID).Return(tCase.directData2.data, tCase.directData2.err).Times(1)
			}
			if tCase.mocks[4] != 0 {
				storage.EXPECT().GetMessagesByDirect(tCase.directID).Return(tCase.messagesData.data, tCase.messagesData.err).Times(1)
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(
				tCase.method,
				"/loadMessenger",
				bytes.NewBuffer([]byte(
					[]byte(tCase.reqData),
				)),
			)

			err := api.loadMessenger(rec, req, tCase.claims)
			require.NoError(t, err)

			res := rec.Result()
			defer res.Body.Close()

			data, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			expectedResp := `{"error":"` + tCase.expData + `"}` + "\n"
			require.Equal(t, expectedResp, string(data))
			require.Equal(t, tCase.expStatus, res.StatusCode)
		})
	}
}
