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

func userauth(resp http.ResponseWriter, req *http.Request, session *httpsession.Session) {
	if req.URL.Path == "/login" {
		if req.PostFormValue("password") == "secret" {
			session.Values()["login"] = true
		}
	}

	loggedIn, _ := session.Values()["login"].(bool)
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

	sessionServer := httpsession.NewSessionServer(
		"websess",
		mapstore.NewMapSessionStore(),
		&sessioncookie.Server{"websess"},
		time.Second*20,
		time.Second*40,
	)

	http.Handle("/", sessionServer.Handle(httpsession.HandlerFunc(userauth)))
	err := http.ListenAndServe(":"+*port, nil)
	if err != nil {
		log.Fatal(err)
	}
}
