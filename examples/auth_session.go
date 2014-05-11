package main

import (
	"flag"
	"fmt"
	"github.com/timob/httpsession"
	"github.com/timob/httpsession/store/mapstore"
	"github.com/timob/httpsession/token/sessioncookie"
	"log"
	"net/http"
	"time"
)

var sessionDB *httpsession.SessionDB = &httpsession.SessionDB{
	mapstore.NewMapSessionStore(),
	time.Second * 30,
	httpsession.DefaultTokenTimeout,
}

func userauth(resp http.ResponseWriter, req *http.Request) {
	token := &sessioncookie.SessionCookie{"login", resp, req}
	session, err := sessionDB.GetSession(token)
	if err != nil {
		http.Error(resp, "error", 500)
		return
	}

	if req.URL.Path == "/login" {
		if req.PostFormValue("password") == "secret" {
			session.Values["login"] = true
		}
	}
	err = sessionDB.SaveSession(session, token)
	if err != nil {
		http.Error(resp, "error", 500)
		return
	}

	loggedIn, _ := session.Values["login"].(bool)
	if loggedIn {
		fmt.Fprint(resp, "Logged In")
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

	http.Handle("/", http.HandlerFunc(userauth))
	err := http.ListenAndServe(":"+*port, nil)
	if err != nil {
		log.Fatal(err)
	}
}
