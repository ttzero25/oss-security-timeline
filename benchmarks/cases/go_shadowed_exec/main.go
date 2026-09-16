package main

import (
	"net/http"
	"os/exec"
)

type localExecutor struct{}

func (localExecutor) Command(arguments ...string) {}

func handler(w http.ResponseWriter, r *http.Request) {
	command := r.FormValue("command")
	_ = exec.ErrNotFound
	exec := localExecutor{}
	exec.Command("sh", "-c", command)
}
