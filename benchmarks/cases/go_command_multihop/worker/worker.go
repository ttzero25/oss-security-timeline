package worker

import "os/exec"

func Execute(value string) {
	exec.Command("sh", "-c", value).Run()
}
