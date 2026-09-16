package main

import (
	"example.test/demo/worker"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	command := r.FormValue("command")
	worker.Execute(command)
}
