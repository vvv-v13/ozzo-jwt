// Copyright 2016  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package auth provides a set of user authentication handlers for the ozzo routing package.
package jwt

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/go-ozzo/ozzo-routing"
	"log"
	"net/http"
	"strings"
	"time"
)

// User is the key used to store and retrieve the user identity information in routing.Context
const User = "User"

type JWTConfig struct {
	SecretKey string
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
type TokenAuthFunc func(c *routing.Context, payload map[string]interface{}) (Payload, error)

// TokenName is the query parameter name for auth token.
var TokenName = "access-token"

// JWT returns a routing.Handler that performs HTTP authentication based on bearer token.
// It can be used like the following:
//
// Example 
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

		token, err := jwt.Parse(header[7:], func(t *jwt.Token) (interface{}, error) { return []byte(jwtConfig.SecretKey), nil })
		if err != nil {
			c.Response.Header().Set("WWW-Authenticate", `Bearer realm="`+name+`"`)
			return routing.NewHTTPError(http.StatusUnauthorized, "ivalid credential")
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

func CreateToken(jwtConfig JWTConfig, payload JWTPayload ) string {
	// Create JWT token
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = payload

	// Expire in 120 minutes
	token.Claims["exp"] = time.Now().Add(time.Minute * 120).Unix()
	tokenString, err := token.SignedString([]byte(jwtConfig.SecretKey))

	if err != nil {
	}

	return tokenString

}
