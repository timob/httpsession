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

func (c *SessionCookie) GetTokenData() (*token.TokenData, bool, error) {
	idCookie, err := c.Req.Cookie(c.Name)
	if err == http.ErrNoCookie {
		return nil, true, nil
	} else if err != nil {
		return nil, false, err
	}
	return token.NewTokenDataFromString(idCookie.Value), false, nil
}

func (c *SessionCookie) SetTokenData(t *token.TokenData) error {
	http.SetCookie(
		c.Resp,
		&http.Cookie{
			Name:     c.Name,
			Value:    t.String(),
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
