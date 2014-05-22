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
	"github.com/timob/httpsession/token/sessioncookie"
	"log"
	"net/http"
	"time"
)

func main() {
	sessionServer := httpsession.NewSessionServer(
		"websess",                        //name
		mapstore.NewMapSessionStore(),    //session store
		&sessioncookie.Server{"websess"}, //token cookie
		time.Second*20,                   //session timeout
		time.Second*40,                   //change cookie timeout
	)

	http.Handle("/", sessionServer.Handle(httpsession.HandlerFunc(
		func(resp http.ResponseWriter, req *http.Request, session *httpsession.Session) {
			if _, ok := session.Values()["counter"]; !ok {
				session.Values()["counter"] = 0
			}

			counter := session.Values()["counter"].(int)
			fmt.Fprintf(resp, "counter = %d", counter)
			session.Values()["counter"] = counter + 1
		},
	)))

	err := http.ListenAndServe(":7878", nil)
	if err != nil {
		log.Fatal(err)
	}
}
```

