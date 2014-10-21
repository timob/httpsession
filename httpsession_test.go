package httpsession

import (
	"github.com/timob/httpsession/store/mapstore"
	"github.com/timob/httpsession/token/sessioncookie"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionCookie(t *testing.T) {
	recorder := httptest.NewRecorder()
	request, _ := http.NewRequest("GET", "http://blah/", nil)

	store := mapstore.NewMapSessionStore()
	cookie := &sessioncookie.SessionCookie{"websess", recorder, request}
	session, token, err := OpenSession(cookie.GetToken(), store)
	if err != nil {
		t.Fatal(err)
	}
	cookie.SetToken(token, time.Minute)
	session.SetVar("hello", "world")
	session.Save(time.Minute * 10)
	err = session.GetLastError()
	t.Logf("recorder %v", recorder)
	if err != nil {
		t.Fatal(err)
	}

	request, _ = http.NewRequest("GET", "http://blah/", nil)
	val := strings.Split(strings.Split(recorder.Header()["Set-Cookie"][0], ";")[0], "websess=")[1]
	request.AddCookie(&http.Cookie{
		Name:  "websess",
		Value: val,
	})
	recorder = httptest.NewRecorder()

	cookie = &sessioncookie.SessionCookie{"websess", recorder, request}
	session, token, err = OpenSession(cookie.GetToken(), store)
	if err != nil {
		t.Fatal(err)
	}
	cookie.SetToken(token, time.Minute)
	v := session.StringVar("hello")
	if v != "world" {
		t.Fatal("expecting session map to be set")
	}
	session.Save(time.Minute * 10)
	err = session.GetLastError()
	t.Logf("recorder %v", recorder)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuthSessionCookie(t *testing.T) {
	recorder := httptest.NewRecorder()
	request, _ := http.NewRequest("GET", "http://blah/", nil)

	store := mapstore.NewMapSessionStore()
	cookie := &sessioncookie.SessionCookie{"websess", recorder, request}
	authCookie := &sessioncookie.SessionCookie{"websessauth", recorder, request}
	session, token, authToken, err := OpenSessionWithAuth(cookie.GetToken(), authCookie.GetToken(), time.Minute*10, store)
	if err != nil {
		t.Fatal(err)
	}
	cookie.SetToken(token, time.Minute)
	authCookie.SetToken(authToken, time.Minute)
	session.SetVar("hello", "world")
	session.Save(time.Minute * 10)
	err = session.GetLastError()
	t.Logf("recorder %v", recorder)
	if err != nil {
		t.Fatal(err)
	}

	request, _ = http.NewRequest("GET", "http://blah/", nil)
	val := strings.Split(strings.Split(recorder.Header()["Set-Cookie"][0], ";")[0], "websess=")[1]
	request.AddCookie(&http.Cookie{
		Name:  "websess",
		Value: val,
	})
	val2 := strings.Split(strings.Split(recorder.Header()["Set-Cookie"][1], ";")[0], "websessauth=")[1]
	request.AddCookie(&http.Cookie{
		Name:  "websessauth",
		Value: val2,
	})
	recorder = httptest.NewRecorder()

	cookie = &sessioncookie.SessionCookie{"websess", recorder, request}
	authCookie = &sessioncookie.SessionCookie{"websessauth", recorder, request}
	session, token, authToken, err = OpenSessionWithAuth(cookie.GetToken(), authCookie.GetToken(), time.Minute*10, store)
	if err != nil {
		t.Fatal(err)
	}
	cookie.SetToken(token, time.Minute)
	authCookie.SetToken(authToken, time.Minute)
	v := session.StringVar("hello")
	if v != "world" {
		t.Fatal("expecting session map to be set")
	}
	session.Save(time.Minute * 10)
	err = session.GetLastError()
	t.Logf("recorder %v", recorder)
	if err != nil {
		t.Fatal(err)
	}
}
