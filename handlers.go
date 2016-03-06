// Copyright (c) 2016, Vitalii Panko <vetal13@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.


// Package auth provides a set of user authentication handlers for the ozzo routing package.
package jwt

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/go-ozzo/ozzo-routing"
	"net/http"
	"strings"
)

// User is the key used to store and retrieve the user identity information in routing.Context
const User = "User"

type JWTConfig struct {
	Alg     string
	Secret  string
	Expires int64
}

// Identity represents an authenticated user. If a user is successfully authenticated by
// an auth handler (Basic, Bearer, or Query), an Identity object will be made available for injection.
type Identity interface{}

type Payload interface{}
type JWTPayload map[string]interface{}

// DefaultRealm is the default realm name for HTTP authentication. It is used by HTTP authentication based on
// Basic and Bearer.
var DefaultRealm = "API"

// TokenAuthFunc is the function for authenticating a user based on a secret token.
type TokenAuthFunc func(c *routing.Context, payload JWTPayload) (Payload, error)

// JWT returns a routing.Handler that performs HTTP authentication based on bearer token.
// It can be used like the following:
//
// import (
//        "github.com/go-ozzo/ozzo-routing"
//        "github.com/vvv-v13/ozzo-jwt"
//        "net/http"
//        "time"
// )
//
// func main() {
// 
//        jwtConfig := jwt.JWTConfig{
//                Alg:     "HS256",
//                Secret:  "super_secret",
//                Expires: time.Now().Add(time.Minute * 120).Unix(),
//        }
//
//        router := routing.New()
//        router.Use(
//                jwt.JWT(func(c *routing.Context, payload jwt.JWTPayload) (jwt.Payload, error) {
//                        return identity(c, payload)
//                }, jwtConfig),
//        )
// 
//        router.Get("/demo", func(c *routing.Context) error {
//                log.Println("User id:", c.Get(jwt.User))
//        })
//
// func identity(c *routing.Context, payload jwt.JWTPayload) (jwt.Identity, error) {
//        if id, ok := payload["id"]; ok {
//                return jwt.Identity(id), nil
//        }
//        return nil, errors.New("invalid credential")
// }
//
// By default, the auth realm is named as "API". You may customize it by specifying the realm parameter.
//
// When authentication fails, a "WWW-Authenticate" header will be sent, and an http.StatusUnauthorized
// error will be reported via routing.Context.Error().

func JWT(fn TokenAuthFunc, jwtConfig JWTConfig, realm ...string) routing.Handler {
	name := DefaultRealm
	if len(realm) > 0 {
		name = realm[0]
	}
	return func(c *routing.Context) error {

		header := c.Request.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.Response.Header().Set("WWW-Authenticate", `Bearer realm="`+name+`"`)
			return routing.NewHTTPError(http.StatusUnauthorized, "ivalid credential")
		}

		token, err := jwt.Parse(header[7:], func(t *jwt.Token) (interface{}, error) { return []byte(jwtConfig.Secret), nil })
		if err != nil {
			c.Response.Header().Set("WWW-Authenticate", `Bearer realm="`+name+`"`)
			return routing.NewHTTPError(http.StatusUnauthorized, err.Error())
		}

		payload := token.Claims

		identity, e := fn(c, payload)
		if e == nil {
			c.Set(User, identity)
			return nil
		}

		c.Response.Header().Set("WWW-Authenticate", `Bearer realm="`+name+`"`)
		return routing.NewHTTPError(http.StatusUnauthorized, e.Error())
	}
}

// CreateToken returns token string
//
// import (
//        "github.com/go-ozzo/ozzo-routing"
//        "github.com/vvv-v13/ozzo-jwt"
//        "net/http"
//        "time"
// )
//
// func main() {
//
//        jwtConfig := jwt.JWTConfig{
//                Alg:     "HS256",
//                Secret:  "super_secret",
//                Expires: time.Now().Add(time.Minute * 120).Unix(),
//        }
//
//        router := routing.New()
//        router.Post("/api/auth", func(c *routing.Context) error { return authHandler(c, jwtConfig) })
//
// func authHandler(c *routing.Context, jwtConfig jwt.JWTConfig) error {
//
//        payload := make(jwt.JWTPayload)
//        payload["id"] = 1
//        payload["role"] = "user"
//
//        token, err := jwt.CreateToken(jwtConfig, payload)
//        if err != nil {
//                return routing.NewHTTPError(http.StatusInternalServerError)
//        }
//
//        data := map[string]string{
//                "token": token,
//        }
//
//        return c.Write(data)
//

func CreateToken(jwtConfig JWTConfig, payload JWTPayload) (string, error) {
	signingMethod := jwt.SigningMethodHS256

	switch jwtConfig.Alg {
	case "HS384":
		signingMethod = jwt.SigningMethodHS384
	case "HS512":
		signingMethod = jwt.SigningMethodHS512
	}

	token := jwt.New(signingMethod)
	token.Claims = payload
	token.Claims["exp"] = jwtConfig.Expires

	tokenString, err := token.SignedString([]byte(jwtConfig.Secret))

	return tokenString, err

}
