package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/nodetide/nodetide/golang/auth"
)

//go:embed web
var webFS embed.FS

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "4557"
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Native SSO (challenge / verify). Login sessions are not implemented in
	// the Go node yet.
	authHandler := auth.NewHandler(os.Getenv("NODETIDE_AUTH_AUDIENCE"))
	authHandler.StartCleanup(time.Minute)

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Post("/auth/challenge", authHandler.Challenge)
		r.Post("/auth/verify", authHandler.Verify)

		r.Post("/identities", createIdentity)
		r.Get("/identities", listIdentities)
		r.Get("/identities/{hash}", getIdentity)
		r.Get("/identities/{hash}/sigchain", getSigchain)
		r.Post("/identities/{hash}/events", submitEvent)
		r.Get("/identities/{hash}/devices", listDevices)

		r.Post("/session", createSession)
		r.Get("/session", getSession)
		r.Delete("/session", deleteSession)

		r.Post("/identities/{hash}/recovery/initiate", initiateRecovery)
		r.Post("/identities/{hash}/recovery/{id}/sign", submitRecoverySignature)
		r.Get("/identities/{hash}/recovery/{id}", getRecoveryStatus)
		r.Get("/identities/{hash}/recovery/pending", listPendingRecoveries)

		r.Post("/trust/delegations", createDelegation)
		r.Get("/trust/delegations", listDelegations)
		r.Get("/trust/calculate/{hash}", calculateTrust)

		r.Post("/verify", verifySigchain)
		r.Get("/lookup/{hash}", lookupIdentity)
	})

	// Serve static files
	webContent, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	fileServer := http.FileServer(http.FS(webContent))
	r.Handle("/*", fileServer)

	log.Printf("Starting server on :%s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}

// API Handlers - Stub implementations

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func errorResponse(w http.ResponseWriter, status int, code, message string) {
	jsonResponse(w, status, map[string]interface{}{
		"error":   code,
		"message": message,
		"code":    status,
	})
}

func createIdentity(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement
	errorResponse(w, 501, "not_implemented", "Go implementation in progress")
}

func listIdentities(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, 200, map[string]interface{}{
		"identities": []interface{}{},
	})
}

func getIdentity(w http.ResponseWriter, r *http.Request) {
	hash := chi.URLParam(r, "hash")
	errorResponse(w, 404, "not_found", "Identity "+hash+" not found")
}

func getSigchain(w http.ResponseWriter, r *http.Request) {
	hash := chi.URLParam(r, "hash")
	errorResponse(w, 404, "not_found", "Identity "+hash+" not found")
}

func submitEvent(w http.ResponseWriter, r *http.Request) {
	errorResponse(w, 501, "not_implemented", "Go implementation in progress")
}

func listDevices(w http.ResponseWriter, r *http.Request) {
	hash := chi.URLParam(r, "hash")
	errorResponse(w, 404, "not_found", "Identity "+hash+" not found")
}

func createSession(w http.ResponseWriter, r *http.Request) {
	errorResponse(w, 501, "not_implemented", "Go implementation in progress")
}

func getSession(w http.ResponseWriter, r *http.Request) {
	errorResponse(w, 401, "unauthorized", "No valid session")
}

func deleteSession(w http.ResponseWriter, r *http.Request) {
	errorResponse(w, 401, "unauthorized", "No valid session")
}

func initiateRecovery(w http.ResponseWriter, r *http.Request) {
	errorResponse(w, 501, "not_implemented", "Go implementation in progress")
}

func submitRecoverySignature(w http.ResponseWriter, r *http.Request) {
	errorResponse(w, 501, "not_implemented", "Go implementation in progress")
}

func getRecoveryStatus(w http.ResponseWriter, r *http.Request) {
	errorResponse(w, 404, "not_found", "Recovery not found")
}

func listPendingRecoveries(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, 200, map[string]interface{}{
		"recoveries": []interface{}{},
	})
}

func createDelegation(w http.ResponseWriter, r *http.Request) {
	errorResponse(w, 501, "not_implemented", "Go implementation in progress")
}

func listDelegations(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, 200, map[string]interface{}{
		"delegations": []interface{}{},
	})
}

func calculateTrust(w http.ResponseWriter, r *http.Request) {
	errorResponse(w, 401, "unauthorized", "Session required")
}

func verifySigchain(w http.ResponseWriter, r *http.Request) {
	errorResponse(w, 501, "not_implemented", "Go implementation in progress")
}

func lookupIdentity(w http.ResponseWriter, r *http.Request) {
	hash := chi.URLParam(r, "hash")
	jsonResponse(w, 200, map[string]interface{}{
		"found":         false,
		"identity_hash": hash,
	})
}
