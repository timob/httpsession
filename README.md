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
	"time"
)

var store = mapstore.NewMapSessionStore()

func main() {
	http.Handle("/", http.HandlerFunc(
		func(resp http.ResponseWriter, req *http.Request) {
			session, _ := httpsession.OpenCookieSession("websess", store, resp, req)
			counter := session.IntVar("counter")
			session.SetVar("counter", counter+1)
			session.Save(time.Minute)
			fmt.Fprintf(resp, "counter = %d", counter)
		},
	))

	err := http.ListenAndServe(":7878", nil)
	if err != nil {
		log.Fatal(err)
	}
}```

