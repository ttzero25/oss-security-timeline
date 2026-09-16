package main

import (
	client "net/http"
)

func proxy(w client.ResponseWriter, r *client.Request) {
	target := r.URL.Query().Get("url")
	client.Get(target)
}
