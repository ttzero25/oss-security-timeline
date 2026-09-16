package main

import (
	"fmt"
	"os"
	"os/exec"
)

func sh(c string) (string, error) {
	cmd := exec.Command("/bin/sh", "-c", c)
	cmd.Env = os.Environ()
	o, err := cmd.CombinedOutput()
	return string(o), err
}

func audioToWav(src, dst string) error {
	out, err := sh(fmt.Sprintf("ffmpeg -i %s -format s16le -ar 16000 -ac 1 -acodec pcm_s16le %s", src, dst))
	if err != nil {
		return fmt.Errorf("error: %w out: %s", err, out)
	}
	return nil
}

func Transcript(audiopath string) error {
	return audioToWav(audiopath, "converted.wav")
}
