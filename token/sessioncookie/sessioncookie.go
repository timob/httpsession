package sessioncookie

import (
	"github.com/timob/httpsession/token"
	"net/http"
)

type SessionCookie struct {
	Name string
	Resp http.ResponseWriter
	Req  *http.Request
}

func (c *SessionCookie) GetTokenData() (*token.TokenData, error) {
	idCookie, err := c.Req.Cookie(c.Name + "_id")
	if err == http.ErrNoCookie {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	tokenCookie, err := c.Req.Cookie(c.Name + "_token")
	if err == http.ErrNoCookie {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &token.TokenData{idCookie.Value, tokenCookie.Value}, nil
}

func (c *SessionCookie) SetTokenData(t *token.TokenData) error {
	http.SetCookie(
		c.Resp,
		&http.Cookie{
			Name:     c.Name + "_id",
			Value:    t.EntryId,
			Path:     "/",
			Domain:   c.Req.URL.Host,
			MaxAge:   60 * 60 * 24 * 365,
			HttpOnly: true,
		},
	)
	http.SetCookie(
		c.Resp,
		&http.Cookie{
			Name:     c.Name + "_token",
			Value:    t.Token,
			Path:     "/",
			Domain:   c.Req.URL.Host,
			MaxAge:   60 * 60 * 24 * 365,
			HttpOnly: true,
		},
	)
	return nil
}

type Server struct {
	CookieName string
}

func (s *Server) Handle(h token.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := &SessionCookie{s.CookieName, w, r}
		h.ServeHTTP(w, r, token)
	}
}
