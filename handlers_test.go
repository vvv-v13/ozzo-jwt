// Copyright (c) 2016, Vitalii Panko <vetal13@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jwt

import (
	"errors"
	"github.com/go-ozzo/ozzo-routing"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func identity(c *routing.Context, payload JWTPayload) (Payload, error) {
	if id, ok := payload["id"]; ok {
		return Payload(id), nil
	}
	return nil, errors.New("invalid credential")

}

func TestJWT(t *testing.T) {

	jwtConfig := JWTConfig{
		Alg:     "HS256",
		Secret:  "super_secret",
		Expires: time.Now().Add(time.Minute * 120).Unix(),
	}

	h := JWT(identity, jwtConfig, "App")

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/users/", nil)
	c := routing.NewContext(res, req)
	err := h(c)
	if assert.NotNil(t, err) {
		assert.Equal(t, "invalid credential", err.Error())
	}
	assert.Equal(t, `Bearer realm="App"`, res.Header().Get("WWW-Authenticate"))
	assert.Nil(t, c.Get(User))

	payload := make(JWTPayload)
	payload["id"] = "user_id"

	token, err := CreateToken(jwtConfig, payload)

	req, _ = http.NewRequest("GET", "/demo/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	c = routing.NewContext(res, req)
	err = h(c)
	assert.Nil(t, err)
	assert.Equal(t, "", res.Header().Get("WWW-Authenticate"))
	assert.Equal(t, "user_id", c.Get(User))

	payload = make(JWTPayload)
	payload["uid"] = "user_id"
	token, err = CreateToken(jwtConfig, payload)

	req, _ = http.NewRequest("GET", "/demo/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	c = routing.NewContext(res, req)
	err = h(c)
	assert.NotNil(t, err)
	assert.Nil(t, c.Get(User))

	req, _ = http.NewRequest("GET", "/demo/", nil)
	req.Header.Set("Authorization", "Bearer QW")
	res = httptest.NewRecorder()
	c = routing.NewContext(res, req)
	err = h(c)
	if assert.NotNil(t, err) {
		assert.Equal(t, "token contains an invalid number of segments", err.Error())
	}
	assert.Equal(t, `Bearer realm="App"`, res.Header().Get("WWW-Authenticate"))
	assert.Nil(t, c.Get(User))
}

func TestCreateToken(t *testing.T) {
	payload := make(JWTPayload)
	payload["id"] = "user_id"

	jwtConfig := JWTConfig{
		Alg:     "HS256",
		Secret:  "super_secret",
		Expires: time.Now().Add(time.Minute * 120).Unix(),
	}

	token, err := CreateToken(jwtConfig, payload)
	assert.Nil(t, err)
	assert.NotNil(t, token)

	jwtConfig = JWTConfig{
		Alg:     "HS384",
		Secret:  "super_secret",
		Expires: time.Now().Add(time.Minute * 120).Unix(),
	}

	token, err = CreateToken(jwtConfig, payload)
	assert.Nil(t, err)
	assert.NotNil(t, token)

	jwtConfig = JWTConfig{
		Alg:     "HS512",
		Secret:  "super_secret",
		Expires: time.Now().Add(time.Minute * 120).Unix(),
	}
	token, err = CreateToken(jwtConfig, payload)
	assert.Nil(t, err)
	assert.NotNil(t, token)
}
