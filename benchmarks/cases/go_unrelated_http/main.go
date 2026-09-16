package main

import http "example.test/symbol/fakehttp"

type Context interface {
	QueryParam(string) string
}

func proxy(c Context) {
	target := c.QueryParam("url")
	http.Get(target)
}
