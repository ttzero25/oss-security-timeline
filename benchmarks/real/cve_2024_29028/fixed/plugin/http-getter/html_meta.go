package getter

import "net/http"

func GetHTMLMeta(urlStr string) error {
	response, err := http.Get(urlStr)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return nil
}
