package error_status

const (
	UserNotFound      = "user not found"
	WrongCredentials  = "wrong credentials"
	WrongUsername     = "wrong username"
	WrongPassword     = "wrong password"
	DirectNotFound    = "direct not found"
	JSONDecodingError = "json decoding error"
	DBError           = "db error"
	EncodeError       = "encoding error"
	BadToken          = "bad token"
	InvalidSign       = "invalid signature"
	InvalidToken      = "invalid token"
	CreateUser        = "something went wrong while creating user"
	NoCookie          = "no cookie"
	ParsingError      = "parsing error"
)
