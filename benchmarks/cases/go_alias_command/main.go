package main

import (
	"net/http"
	runner "os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	command := r.FormValue("command")
	runner.Command("sh", "-c", command).Run()
}
