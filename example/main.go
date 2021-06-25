package main

import (
	"log"
	"net/http"

	"fmt"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	sgj "github.com/davedotdev/silvergorillajwt"
	"github.com/form3tech-oss/jwt-go"
	"github.com/gorilla/mux"
)

// Example use
func basichandler(w http.ResponseWriter, r *http.Request) {
	// This basic handler uses headers inserted by middleware
	// for auth capabilities.

	const handlerName = "/"

	if ret := sgj.CorsHeaders(handlerName, &w, r); ret {
		return
	}

	fmt.Println("serving: ", handlerName)

	// These headers can be used for doing auth/role checking
	fmt.Println(w.Header().Get("JWT-Sub-ID"))
	fmt.Println(w.Header().Get("JWT-Scopes"))
	fmt.Println(w.Header().Get("JWT-Roles"))

	w.Header().Set("Content-Type", "application/text")

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("JWT is valid and you're authorized\n"))
}

func main() {

	sg := sgj.SilverGorilla{
		IssStr:  "http://server/auth/realms/testrealm",
		CertURL: "http://server/auth/realms/testrealm/protocol/openid-connect/certs",
	}

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: sg.ValidationKeyGetter,
		SigningMethod:       jwt.SigningMethodRS256,
	})

	r := mux.NewRouter()

	// This middleware chain: jwtMiddleware -> silvergorillaMiddlewareHandler -> our function
	r.Handle("/", jwtMiddleware.Handler(sg.SilverGorillaMiddlewareHandler(http.HandlerFunc(basichandler))))

	log.Println("starting server on :4050")
	err := http.ListenAndServe(":4050", r)
	log.Fatal(err)
}
