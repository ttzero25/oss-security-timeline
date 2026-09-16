package main

type TranscriptRequest struct {
	Dst string
}

type Whisper struct{}

func (sd *Whisper) AudioTranscription(opts *TranscriptRequest) error {
	return Transcript(opts.Dst)
}
