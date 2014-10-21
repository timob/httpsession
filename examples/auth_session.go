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

var store = mapstore.NewMapSessionStore()

func userauth(resp http.ResponseWriter, req *http.Request) {
	session, err := httpsession.OpenCookieSession("websession", store, resp, req)
	if err != nil {
		log.Print(err)
		http.Error(resp, "internal error", 500)
		return
	}
	if req.URL.Path == "/login" {
		if req.PostFormValue("password") == "secret" {
			session.SetVar("login", true)
		}
	} else if req.URL.Path == "/logout" {
		session.New()
	}
	session.Save(time.Second * 15)
	if err = session.GetLastError(); err != nil {
		log.Print(err)
		http.Error(resp, "internal error", 500)
		return
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

	http.Handle("/", http.HandlerFunc(userauth))
	err := http.ListenAndServe(":"+*port, nil)
	if err != nil {
		log.Fatal(err)
	}
}
