package token

import (
	"net/http"
)

type Handler interface {
	ServeHTTP(http.ResponseWriter, *http.Request, SessionToken)
}

type HandlerFunc func(http.ResponseWriter, *http.Request, SessionToken)

func (h HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request, t SessionToken) {
	h(w, r, t)
}

type Server interface {
	Handle(h Handler) http.HandlerFunc
}
