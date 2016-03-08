// Copyright (c) 2016, Vitalii Panko <vetal13@gmail.com>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"github.com/go-ozzo/ozzo-routing"
	"github.com/go-ozzo/ozzo-routing/access"
	"github.com/go-ozzo/ozzo-routing/content"
	"github.com/go-ozzo/ozzo-routing/fault"
	"github.com/go-ozzo/ozzo-routing/slash"
	"github.com/vvv-v13/ozzo-jwt"
	"log"
	"net/http"
	"time"
)

func main() {

	jwtConfig := jwt.JWTConfig{
		Alg:     "HS256",
		Secret:  "super_secret",
		Expires: time.Minute * 120,
	}

	router := routing.New()
	router.Use(
		access.Logger(log.Printf),
		slash.Remover(http.StatusMovedPermanently),
		content.TypeNegotiator(content.JSON),
		fault.Recovery(log.Printf),
	)

	router.Post("/api/auth", func(c *routing.Context) error { return authHandler(c, jwtConfig) })

	api := router.Group("/api")
	api.Use(
		jwt.JWT(func(c *routing.Context, payload jwt.JWTPayload) (jwt.Payload, error) {
			return identity(c, payload)
		}, jwtConfig),
	)

	api.Get("/posts", func(c *routing.Context) error { return posts(c) })

	// Http server
	server := &http.Server{
		Addr:           ":8080",
		Handler:        nil,
		ReadTimeout:    100 * time.Second,
		WriteTimeout:   100 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	// Router
	http.Handle("/", router)

	// Start HTTP server
	log.Println("Server listen on 8080")
	panic(server.ListenAndServe())
}

func authHandler(c *routing.Context, jwtConfig jwt.JWTConfig) error {

	payload := make(jwt.JWTPayload)
	payload["id"] = 1
	payload["role"] = "user"

	token, err := jwt.CreateToken(jwtConfig, payload)
	if err != nil {
		return routing.NewHTTPError(http.StatusInternalServerError)
	}

	data := map[string]string{
		"token": token,
	}

	return c.Write(data)
}

func identity(c *routing.Context, payload jwt.JWTPayload) (jwt.Identity, error) {
	if id, ok := payload["id"]; ok {
		return jwt.Identity(id), nil
	}
	return nil, errors.New("invalid credential")
}

type Post struct {
	Id      int64  `json:"id"`
	Message string `json:"message"`
}

func posts(c *routing.Context) error {
	log.Println("User id:", c.Get(jwt.User))
	var posts []Post

	post := Post{
		Id:      1,
		Message: "Message",
	}
	posts = append(posts, post)
	return c.Write(posts)
}
