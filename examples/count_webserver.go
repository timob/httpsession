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

var sessionDB = &httpsession.SessionDB{
	mapstore.NewMapSessionStore(),
	time.Second * 20,
	time.Second * 80,
}

func counter(resp http.ResponseWriter, req *http.Request) {
	token := &sessioncookie.SessionCookie{"websess", resp, req}
	session, err := sessionDB.GetSession(token)
	if err != nil {
		http.Error(resp, "error", 500)
		return
	}

	var count int
	v, ok := session.Values["counter"]
	if ok {
		count = v.(int)
	} else {
		count = 0
	}

	count++

	session.Values["counter"] = count

	err = session.Save()
	if err != nil {
		http.Error(resp, "error", 500)
		return
	}

	fmt.Fprintf(resp, "counter = %d", count)
}

func main() {
	port := flag.String("port", "7878", "port")
	flag.Parse()

	http.Handle("/", http.HandlerFunc(counter))
	err := http.ListenAndServe(":"+*port, nil)
	if err != nil {
		log.Fatal(err)
	}
}
