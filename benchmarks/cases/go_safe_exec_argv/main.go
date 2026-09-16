package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	exec.Command("printf", "%s", name).Run()
}
