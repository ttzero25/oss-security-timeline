package main

import (
	"net/http"
)

func proxy(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("url")
	http.Get(target)
}
