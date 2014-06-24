package main

import (
	"flag"
	"fmt"
	"github.com/timob/httpsession"
	"github.com/timob/httpsession/store/mapstore"
	"log"
	"net/http"
	"time"
)

func userauth(resp http.ResponseWriter, req *http.Request, session *httpsession.CookieSession) {
	if req.URL.Path == "/login" {
		if req.PostFormValue("password") == "secret" {
			session.SetVar("login", true)
		}
	} else if req.URL.Path == "/logout" {
		// Create a new session, by clearing values and recreating session
		session.Clear()
		session.Recreate()
	}

	if session.BoolVar("login") {
		fmt.Fprint(resp, `<html> Logged In (<a href="/logout">log out</a>)`)
	} else {
		fmt.Fprint(resp, `<html>
		Logged Out
		<form method="POST" action="/login">
		<input name="password" type="text"></input>
		<input type="submit"></input>
		</form>
		</html>
		`)
	}
}

func main() {
	port := flag.String("port", "7879", "port")
	flag.Parse()

	sessionServer := &httpsession.SessionServer{Name: "websess", Store: mapstore.NewMapSessionStore(), AuthTokenTimeout: time.Second * 15}

	http.Handle("/", sessionServer.Handle(httpsession.HandlerFunc(userauth)))
	err := http.ListenAndServe(":"+*port, nil)
	if err != nil {
		log.Fatal(err)
	}
}
