package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/RangelReale/osin"
	"github.com/RangelReale/osin/example"
	"github.com/gorilla/mux"

	"gopkg.in/square/go-jose.v1"
)

var (
	issuer    = "http://localhost:8080"
	server    = osin.NewServer(osin.NewServerConfig(), example.NewTestStorage())
	jwtSigner jose.Signer
	jwtKeys   *jose.JsonWebKeySet
)

func init() {
	privateKey, _ := createPrivateKey()
	publicKey := &privateKey.PublicKey
	jwk := jose.JsonWebKey{
		Key:       privateKey,
		Algorithm: "RS256",
		Use:       "sig",
		KeyID:     "1",
	}
	_jwtSigner, err := jose.NewSigner(jose.RS256, &jwk)
	if err != nil {
		log.Fatalf("failed to create signer: %v", err)
	}
	jwtSigner = _jwtSigner
	jwtKeys = &jose.JsonWebKeySet{
		Keys: []jose.JsonWebKey{
			jose.JsonWebKey{
				Key:       publicKey,
				Algorithm: "RS256",
				Use:       "sig",
				KeyID:     "1",
			},
		},
	}
}

// Custom claims supported by this server.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
type IDToken struct {
	Issuer        string `json:"iss"`
	UserID        string `json:"sub"`
	ClientID      string `json:"aud"`
	Expiration    int64  `json:"exp"`
	IssuedAt      int64  `json:"iat"`
	Nonce         string `json:"nonce,omitempty"` // Non-manditory fields MUST be "omitempty"
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`

	Name       string `json:"name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
	GivenName  string `json:"given_name,omitempty"`
	Locale     string `json:"locale,omitempty"`
}

func main() {
	r := mux.NewRouter()

	r.Path("/.well-known/openid-configuration").Methods("GET").HandlerFunc(handleDiscovery)
	r.Path("/publickeys").Methods("GET").HandlerFunc(handlePublicKey)
	r.Path("/authorize").Methods("GET", "POST").HandlerFunc(handleAuthorization)
	r.Path("/token").Methods("POST").HandlerFunc(handleToken)

	log.Println("Start server on port 8080...\nPlease [ENTER] stop server")
	go http.ListenAndServe(":8080", r)

	bufio.NewScanner(os.Stdin).Scan()

	log.Println("Bye Bye")
}

func handleDiscovery(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"issure":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/publickeys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"claims_supported": []string{
			"aud", "email", "email_verified", "exp", "family_name",
			"given_name", "iat", "iss", "locale", "name", "sub",
		},
	}

	body, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("failed to marshal data: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}
	renderJSON(w, body)
}

func handlePublicKey(w http.ResponseWriter, r *http.Request) {
	body, err := json.MarshalIndent(jwtKeys, "", "  ")
	if err != nil {
		log.Printf("failed to marshal data: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}
	renderJSON(w, body)
}

func handleAuthorization(w http.ResponseWriter, r *http.Request) {
	resp := server.NewResponse()
	defer resp.Close()

	if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
		// not send user id and password, render login page and return.
		if !example.HandleLoginPage(ar, w, r) {
			return
		}

		ar.Authorized = true
		scopes := make(map[string]bool)
		for _, s := range strings.Fields(ar.Scope) {
			scopes[s] = true
		}

		if scopes["openid"] {
			now := time.Now()
			idToken := IDToken{
				Issuer:     issuer,
				UserID:     "test-user",
				ClientID:   ar.Client.GetId(),
				Expiration: now.Add(time.Hour).Unix(),
				IssuedAt:   now.Unix(),
				Nonce:      r.URL.Query().Get("nonce"),
			}

			if scopes["profile"] {
				idToken.Name = "Jane Doe"
				idToken.GivenName = "Jane"
				idToken.FamilyName = "Due"
				idToken.Locale = "en"
			}

			if scopes["email"] {
				t := true
				idToken.Email = "jane.doe@example.com"
				idToken.EmailVerified = &t
			}

			ar.UserData = &idToken
		}
		server.FinishAuthorizeRequest(resp, r, ar)
	}

	if resp.IsError && resp.InternalError != nil {
		log.Printf("internal error: %v", resp.InternalError)
	}
	osin.OutputJSON(resp, w, r)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	resp := server.NewResponse()
	defer resp.Close()

	// XXX Should verfy client

	if ar := server.HandleAccessRequest(resp, r); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, r, ar)

		if idToken, ok := ar.UserData.(*IDToken); ok && idToken != nil {
			encodeIDToken(resp, idToken)
		}
	}
	if resp.IsError && resp.InternalError != nil {
		log.Printf("internal error: %v", resp.InternalError)
	}
	osin.OutputJSON(resp, w, r)
}

func renderJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Write(body)
}

func encodeIDToken(resp *osin.Response, idToken *IDToken) {
	resp.InternalError = func() error {
		payload, err := json.Marshal(idToken)
		if err != nil {
			return fmt.Errorf("failed to marshal token: %v", err)
		}
		jws, err := jwtSigner.Sign(payload)
		if err != nil {
			return fmt.Errorf("failed to sign token: %v", err)
		}
		body, err := jws.CompactSerialize()
		if err != nil {
			return fmt.Errorf("failed to serialize token: %v", err)
		}
		resp.Output["id_token"] = body
		return nil
	}()
	if resp.InternalError != nil {
		resp.IsError = true
		resp.ErrorId = osin.E_SERVER_ERROR
	}
}

func createPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
