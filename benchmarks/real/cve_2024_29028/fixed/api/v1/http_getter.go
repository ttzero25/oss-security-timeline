package v1

import "github.com/labstack/echo/v4"

func (*APIV1Service) registerGetterPublicRoutes(g *echo.Group) {
	g.GET("/get/image", GetImage)
}
