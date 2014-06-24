httpsession
==========
Go HTTP session library

Documentation
-------------
http://godoc.org/github.com/timob/httpsession

Example
-------
```Go
package main

import (
	"fmt"
	"github.com/timob/httpsession"
	"github.com/timob/httpsession/store/mapstore"
	"log"
	"net/http"
)

func main() {
	sessionServer := &httpsession.SessionServer{Name: "websess", Store: mapstore.NewMapSessionStore()}

	http.Handle("/", sessionServer.Handle(httpsession.HandlerFunc(
		func(resp http.ResponseWriter, req *http.Request, session *httpsession.CookieSession) {
			counter := session.IntVar("counter")
			fmt.Fprintf(resp, "counter = %d", counter)
			session.SetVar("counter", counter+1)
		},
	)))

	err := http.ListenAndServe(":7878", nil)
	if err != nil {
		log.Fatal(err)
	}
}```

