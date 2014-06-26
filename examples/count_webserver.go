package main

import (
	"flag"
	"fmt"
	"github.com/timob/httpsession"
	"github.com/timob/httpsession/store/mapstore"
	"github.com/timob/httpsession/token"
	"log"
	"net/http"
	"net/url"
	"time"
)

var mapStore = mapstore.NewMapSessionStore()

func counter(resp http.ResponseWriter, req *http.Request) {
	var err error
	defer func() {
		if err != nil {
			http.Error(resp, "error", 500)
		}
	}()

	args, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return
	}
	sessionArg := token.TokenStr(args.Get("session"))

	session, sessionToken, err := httpsession.OpenSession(sessionArg, mapStore)
	if err != nil {
		return
	}
	defer func() {
		session.Save(time.Second * 40)
		err = session.GetLastError()
	}()

	if sessionToken != sessionArg {
		args.Set("session", sessionToken.String())
		req.URL.RawQuery = args.Encode()
		resp.Header().Set("Location", req.URL.String())
		http.Error(resp, "See Other", 303)
		return
	}

	count := session.IntVar("counter")
	count++
	session.SetVar("counter", count)
	fmt.Fprintf(resp, "counter = %d, lastupdate %s", count, session.DurationSinceLastUpdate())
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
