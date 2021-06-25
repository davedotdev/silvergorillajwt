package main

import (
	"encoding/json"
	"log"
	"net/http"

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

	// These headers can be used for doing auth/role checking
	sub := w.Header().Get("JWT-Sub-ID")
	scopes := w.Header().Get("JWT-Scopes")
	roles := w.Header().Get("JWT-Roles")

	type Headers struct {
		Sub     string `json:"sub"`
		Scopes  string `json:"scopes"`
		Roles   string `json:"roles"`
		Message string `json:"message"`
	}

	headerStruct := Headers{Sub: sub, Scopes: scopes, Roles: roles, Message: "JWT is valid and you're authorized"}
	returnBytes, err := json.Marshal(headerStruct)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(returnBytes))
}

func main() {

	// These are keycloak examples. Ensure your realm and server address fields are correct.
	sg := sgj.SilverGorilla{
		IssStr:  "https://192.168.50.100:8443/auth/realms/testrealm",
		CertURL: "https://192.168.50.100:8443/auth/realms/testrealm/protocol/openid-connect/certs",
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
