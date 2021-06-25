package silvergorillajwt

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"fmt"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
	"github.com/gorilla/mux"
)

/*
	***************************************************************************
					READ ME PROPERLY - or else, you'll be late
	***************************************************************************

	This middleware works with Gorilla Mux, validates a JWT token and adds
	headers to the response. Other middleware or HTTP handlers can then use the headers
	to process data. Because the JWT was validated beforehand, we can safely assume data integrity
	unless someone found a way to poke program memory. In which case we have bigger problems.


	- Integrate Gorilla Mux
	- Enforce JWT validation
	- Enforce scope presence by adding headers by propagation of response
*/

type SilverGorilla struct {
	issStr  string // issuer string for keycloak this would look like: http://{server}/auth/realms/{realm}
	CertURL string // certificates, for example with KeyCloak this would be /auth/realms/{realm}/protocol/openid-connect/certs
}

func (sg SilverGorilla) getPemCert(token *jwt.Token) (string, error) {
	cert := ""
	resp, err := http.Get(sg.CertURL)

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("unable to find appropriate key")
		return cert, err
	}

	return cert, nil
}

func (sg SilverGorilla) validationKeyGetter(token *jwt.Token) (interface{}, error) {

	// Verify 'iss' claim
	checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(sg.issStr, false)
	if !checkIss {
		fmt.Println("JWT error: invalid issuer")
		return token, errors.New("invalid issuer")
	}

	cert, err := sg.getPemCert(token)
	if err != nil {
		panic(err.Error())
	}

	result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
	return result, nil
}

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type CustomClaims struct {
	Scope       string              `json:"scope"`
	RealmAccess map[string][]string `json:"realm_access"`
	jwt.StandardClaims
}

func setupCorsResponse(w *http.ResponseWriter, req *http.Request) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Authorization")
}

func corsHeaders(name string, w *http.ResponseWriter, req *http.Request) bool {
	fmt.Printf("%v: checking for preflight and key\n", name)
	if (*req).Method == "OPTIONS" {
		setupCorsResponse(w, req)
		return true
	}

	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	return false
}

func (sg SilverGorilla) getScopesandSub(tokenString string) (scopes []string, realmroles []string, sub string, err error) {

	if tokenString == "" {
		err = errors.New("getScopesandSub: no Authorization header found")
		return
	}

	tokenStrings := strings.Split(tokenString, "Bearer ")
	// We don't need to check for the correct header. If it isn't present, we wouldnt' get this far.
	if len(tokenStrings) == 0 || len(tokenStrings) < 2 {
		err = errors.New("getScopesandSub: issue with Authorization header")
		return
	}

	tokenString = tokenStrings[1]

	token, err := jwt.ParseWithClaims(
		tokenString, &CustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			claims, ok := token.Claims.(*CustomClaims)
			if !ok {
				fmt.Println(claims)
				return nil, errors.New("error parsing claims")

			}
			sub = claims.Subject

			cert, err := sg.getPemCert(token)
			if err != nil {
				fmt.Println("error with getPemCert()")
				panic(err.Error())
			}

			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			return result, nil
		},
	)

	// Check for errors
	// The one without an error is the one used

	if err != nil {
		return []string{""}, []string{""}, "", err
	}

	claims, ok := token.Claims.(*CustomClaims)

	if ok && token.Valid {
		rscopes := strings.Split(claims.Scope, " ")
		scopes = append(scopes, rscopes...)

		realmroles = append(realmroles, claims.RealmAccess["roles"]...)
	}

	return realmroles, scopes, sub, nil
}

func (sg SilverGorilla) silvergorillaMiddlewareHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		AuthHeader := ""
		AuthHeader = r.Header.Get("Authorization")
		roles, scopes, sub, err := sg.getScopesandSub(AuthHeader)

		if err != nil {
			h.ServeHTTP(w, r)
			return
		}

		w.Header().Add("JWT-Sub-ID", sub)

		scopeStr := ""
		lenScopes := len(scopes)

		for k, v := range scopes {
			scopeStr = scopeStr + v
			if k != lenScopes {
				scopeStr = scopeStr + " "
			}
		}

		w.Header().Add("JWT-Scopes", scopeStr)

		roleStr := ""
		lenRoles := len(roles)

		for k, v := range roles {
			roleStr = roleStr + v
			if k != lenRoles {
				roleStr = roleStr + " "
			}
		}

		w.Header().Add("JWT-Roles", roleStr)

		h.ServeHTTP(w, r)
	})
}

// Example use

func basichandler(w http.ResponseWriter, r *http.Request) {
	// This basic handler uses headers inserted by middleware
	// for auth capabilities.

	const handlerName = "/"

	if ret := corsHeaders(handlerName, &w, r); ret {
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

	sg := SilverGorilla{
		issStr:  "http://server/auth/realms/testrealm",
		CertURL: "http://server/auth/realms/testrealm/protocol/openid-connect/certs",
	}

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: sg.validationKeyGetter,
		SigningMethod:       jwt.SigningMethodRS256,
	})

	r := mux.NewRouter()

	// This middleware chain: jwtMiddleware -> silvergorillaMiddlewareHandler -> our function
	r.Handle("/", jwtMiddleware.Handler(sg.silvergorillaMiddlewareHandler(http.HandlerFunc(basichandler))))

	log.Println("starting server on :4050")
	err := http.ListenAndServe(":4050", r)
	log.Fatal(err)
}
