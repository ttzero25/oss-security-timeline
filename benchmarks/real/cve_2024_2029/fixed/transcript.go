package main

import (
	"fmt"
	"os"
	"os/exec"
)

func runCommand(command []string) (string, error) {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func audioToWav(src, dst string) error {
	command := []string{"ffmpeg", "-i", src, "-format", "s16le", "-ar", "16000", "-ac", "1", "-acodec", "pcm_s16le", dst}
	out, err := runCommand(command)
	if err != nil {
		return fmt.Errorf("error: %w out: %s", err, out)
	}
	return nil
}

func Transcript(audiopath string) error {
	return audioToWav(audiopath, "converted.wav")
}
