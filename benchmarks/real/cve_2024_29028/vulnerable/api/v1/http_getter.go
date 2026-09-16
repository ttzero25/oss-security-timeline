package v1

import (
	"net/http"

	"github.com/labstack/echo/v4"
	getter "github.com/usememos/memos/plugin/http-getter"
)

func GetWebsiteMetadata(c echo.Context) error {
	urlStr := c.QueryParam("url")
	if urlStr == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing website url")
	}
	htmlMeta, err := getter.GetHTMLMeta(urlStr)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, htmlMeta)
}
