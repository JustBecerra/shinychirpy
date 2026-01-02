package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"shinychirpy/internal/auth"
	"shinychirpy/internal/database"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	tokenSecret    string
}

type User struct {
	ID             uuid.UUID `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Email          string    `json:"email"`
	HashedPassword string    `json:"-"`
}

type Chirp struct {
	Id        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserId    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())
}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	cfg.db.DeleteAllUsers(r.Context())
	if cfg.platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func filterProphane(body string) string {
	words := []string{"kerfuffle", "sharbert", "fornax"}
	result := body

	for _, word := range words {
		lowerWord := strings.ToLower(word)
		lowerBody := strings.ToLower(result)

		for {
			idx := strings.Index(lowerBody, lowerWord)
			if idx == -1 {
				break
			}
			// Replace the word in the original case-preserved string
			result = result[:idx] + "****" + result[idx+len(word):]
			// Update lowercase version for next search
			lowerBody = strings.ToLower(result)
		}
	}

	return result
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	err := json.NewEncoder(w).Encode(payload)
	if err != nil {
		fmt.Println("Error encoding JSON:", err)
	}
}

func respondWithError(w http.ResponseWriter, code int) {
	w.WriteHeader(code)
	err := json.NewEncoder(w).Encode(map[string]string{"error": http.StatusText(code)})
	if err != nil {
		fmt.Println("Error encoding JSON:", err)
	}
}

func (cfg *apiConfig) handlerCreateChirps(w http.ResponseWriter, r *http.Request) {
	type createChirpRequest struct {
		Body string `json:"body"`
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.tokenSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized)
		return
	}

	decoder := json.NewDecoder(r.Body)
	req := createChirpRequest{}
	err = decoder.Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest)
		return
	}

	if len(req.Body) > 140 {
		respondWithError(w, http.StatusBadRequest)
		return
	}

	chirp, err := cfg.db.CreateChirps(r.Context(), database.CreateChirpsParams{
		Body:   req.Body,
		UserID: userID,
	})
	if err != nil {
		fmt.Println("Error creating chirp:", err)
		respondWithError(w, http.StatusInternalServerError)
		return
	}

	respondWithJSON(w, http.StatusCreated, Chirp{
		Id:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserId:    chirp.UserID,
	})
}

func (cfg *apiConfig) handlerCreateUser(w http.ResponseWriter, r *http.Request) {
	type createUserRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	req := createUserRequest{}
	err := decoder.Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest)
		return
	}

	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		fmt.Println("Error hashing password:", err)
		respondWithError(w, http.StatusInternalServerError)
		return
	}

	user, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          req.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		fmt.Println("Error creating user:", err)
		respondWithError(w, http.StatusInternalServerError)
		return
	}

	respondWithJSON(w, http.StatusCreated, User{
		ID:             user.ID,
		CreatedAt:      user.CreatedAt,
		UpdatedAt:      user.UpdatedAt,
		Email:          user.Email,
		HashedPassword: user.HashedPassword,
	})
}

func (cfg *apiConfig) handlerLoginUser(w http.ResponseWriter, r *http.Request) {
	type loginUserRequest struct {
		Email            string `json:"email"`
		Password         string `json:"password"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}

	type loginUserResponse struct {
		User
		Token string `json:"token"`
	}

	decoder := json.NewDecoder(r.Body)
	req := loginUserRequest{}
	err := decoder.Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest)
		return
	}

	user, err := cfg.db.RetrieveUserByEmail(r.Context(), req.Email)
	if err != nil {
		fmt.Println("Error retrieving user:", err)
		respondWithError(w, http.StatusUnauthorized)
		return
	}

	checkedPassword, err := auth.CheckPasswordHash(req.Password, user.HashedPassword)
	if err != nil {
		fmt.Println("Error checking password:", err)
		respondWithError(w, http.StatusUnauthorized)
		return
	}

	if !checkedPassword {
		respondWithError(w, http.StatusUnauthorized)
		return
	}

	expiresInSeconds := req.ExpiresInSeconds
	if expiresInSeconds == 0 {
		expiresInSeconds = 3600 // Default to 1 hour
	}
	if expiresInSeconds > 3600 {
		expiresInSeconds = 3600 // Cap at 1 hour
	}

	token, err := auth.MakeJWT(user.ID, cfg.tokenSecret, time.Duration(expiresInSeconds)*time.Second)
	if err != nil {
		fmt.Println("Error creating JWT:", err)
		respondWithError(w, http.StatusInternalServerError)
		return
	}

	respondWithJSON(w, http.StatusOK, loginUserResponse{
		User: User{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			Email:     user.Email,
		},
		Token: token,
	})
}

func (cfg *apiConfig) handlerRetrieveChirpsAscOrder(w http.ResponseWriter, r *http.Request) {
	dbChirps, err := cfg.db.RetrieveChirpsAscOrder(r.Context())
	if err != nil {
		fmt.Println("Error retrieving chirps:", err)
		respondWithError(w, http.StatusInternalServerError)
		return
	}

	chirps := make([]Chirp, len(dbChirps))
	for i, dbChirp := range dbChirps {
		chirps[i] = Chirp{
			Id:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body:      dbChirp.Body,
			UserId:    dbChirp.UserID,
		}
	}

	respondWithJSON(w, http.StatusOK, chirps)
}

func (cfg *apiConfig) handlerRetrieveSingleChirp(w http.ResponseWriter, r *http.Request) {
	chirpID := r.PathValue("chirpID")
	dbChirp, err := cfg.db.RetrieveSingleChirp(r.Context(), uuid.MustParse(chirpID))
	if err != nil {
		fmt.Println("Error retrieving chirp:", err)
		respondWithError(w, http.StatusNotFound)
		return
	}

	respondWithJSON(w, http.StatusOK, Chirp{
		Id:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserId:    dbChirp.UserID,
	})

}

func (cfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, r *http.Request) {
	type updateUserRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	req := updateUserRequest{}
	err := decoder.Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest)
		return
	}

	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		fmt.Println("Error hashing password:", err)
		respondWithError(w, http.StatusInternalServerError)
		return
	}

	user, err := cfg.db.UpdateUser(r.Context(), database.UpdateUserParams{
		ID:             uuid.MustParse(r.PathValue("userId")),
		Email:          req.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		fmt.Println("Error updating user:", err)
		respondWithError(w, http.StatusInternalServerError)
		return
	}

	respondWithJSON(w, http.StatusOK, User{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
	})
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	tokenSecret := os.Getenv("SECRET_TOKEN")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Println("Error opening database:", err)
	}
	dbQueries := database.New(db)
	cfg := &apiConfig{
		db:          dbQueries,
		platform:    platform,
		tokenSecret: tokenSecret,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	mux.HandleFunc("GET /api/chirps", cfg.handlerRetrieveChirpsAscOrder)
	mux.HandleFunc("GET /api/chirps/{chirpID}", cfg.handlerRetrieveSingleChirp)
	mux.HandleFunc("GET /admin/metrics", cfg.handlerMetrics)
	mux.HandleFunc("POST /admin/reset", cfg.handlerReset)
	mux.HandleFunc("POST /api/chirps", cfg.handlerCreateChirps)
	mux.HandleFunc("POST /api/users", cfg.handlerCreateUser)
	mux.HandleFunc("POST /api/login", cfg.handlerLoginUser)
	mux.HandleFunc("PUT api/users", cfg.handlerUpdateUser)
	mux.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	mux.Handle("/assets/logo", http.FileServer(http.Dir(".")))
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	server.ListenAndServe()
}
