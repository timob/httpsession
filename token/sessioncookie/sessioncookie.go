package sessioncookie

import (
	"github.com/timob/httpsession/token"
	"net/http"
	"time"
)

type SessionCookie struct {
	Name string
	Resp http.ResponseWriter
	Req  *http.Request
}

func (c *SessionCookie) GetToken() token.Token {
	idCookie, err := c.Req.Cookie(c.Name)
	if err == http.ErrNoCookie {
		return token.EmptyToken
	}
	return token.TokenStr(idCookie.Value)
}

func (c *SessionCookie) SetToken(t token.Token, d time.Duration) {
	var val string
	var maxAge int
	if !t.IsEmpty() {
		val = t.String()
		maxAge = int(d.Seconds())
	} else {
		val = ""
		maxAge = -1
	}
	http.SetCookie(
		c.Resp,
		&http.Cookie{
			Name:     c.Name,
			Value:    val,
			Path:     "/",
			Domain:   c.Req.URL.Host,
			MaxAge:   maxAge,
			HttpOnly: true,
		},
	)
	return
}

func (c *SessionCookie) Remove() {
	c.SetToken(token.EmptyToken, 0)
}
