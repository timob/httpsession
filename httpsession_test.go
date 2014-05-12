package httpsession

import (
	"github.com/timob/httpsession/store/mapstore"
	"github.com/timob/httpsession/token/sessioncookie"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSessionCookie(t *testing.T) {
	recorder := httptest.NewRecorder()
	request, _ := http.NewRequest("GET", "http://blah/", nil)

	sessionDB := &SessionDB{
		mapstore.NewMapSessionStore(),
		DefaultSessionTimeout,
		DefaultTokenTimeout,
	}

	token := &sessioncookie.SessionCookie{"websess", recorder, request}
	session, err := sessionDB.GetSession(token)
	if err != nil {
		t.Fatal(err)
	}
	session.Values["hello"] = "world"
	err = session.Save()
	t.Logf("recorder %v", recorder)
	if err != nil {
		t.Fatal(err)
	}

	request, _ = http.NewRequest("GET", "http://blah/", nil)
	val := strings.Split(strings.Split(recorder.Header()["Set-Cookie"][0], ";")[0], "websess_id=")[1]
	request.AddCookie(&http.Cookie{
		Name:  "websess_id",
		Value: val,
	})
	val2 := strings.Split(strings.Split(recorder.Header()["Set-Cookie"][1], ";")[0], "websess_token=")[1]
	request.AddCookie(&http.Cookie{
		Name:  "websess_token",
		Value: val2,
	})
	recorder = httptest.NewRecorder()

	token = &sessioncookie.SessionCookie{"websess", recorder, request}
	session, err = sessionDB.GetSession(token)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := session.Values["hello"]
	if !ok || v.(string) != "world" {
		t.Fatal("expecting session map to be set")
	}
	err = session.Save()
	t.Logf("recorder %v", recorder)
	if err != nil {
		t.Fatal(err)
	}
}
