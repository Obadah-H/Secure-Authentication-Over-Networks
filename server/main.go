package main

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/sha3"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

// Request represents the incoming client request
type Request struct {
	Code          string `json:"code"`
	Hash          string `json:"hash"`
	Email         string `json:"email"`
	HashAlgorithm string `json:"hash_algorithm"`
}

// Response represents the server response
type Response struct {
	Success   bool        `json:"success"`
	Message   string      `json:"message"`
	UserFound bool        `json:"user_found"`
	UserData  interface{} `json:"user_data,omitempty"`
	Hash      string      `json:"hash,omitempty"`
}

// User represents a user in the database
type User struct {
	ID        int    `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Hash      string `json:"hash"`
	Salt      string `json:"salt"`
	Code      string `json:"code"`
	CreatedAt string `json:"created_at,omitempty"`
}

// Server holds the application dependencies
type Server struct {
	db     *sql.DB
	config *Config
}

// Config holds the server configuration
type Config struct {
	DBHost     string
	DBPort     int
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string
	ServerPort string
}

func main() {
	// Load configuration
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Connect to database
	db, err := connectDB(config)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	// Test database connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Error pinging database: %v", err)
	}
	log.Println("Successfully connected to database")

	// Create server
	server := &Server{
		db:     db,
		config: config,
	}

	// Setup routes
	http.HandleFunc("/api/check-hash", server.handleCheckHash)
	http.HandleFunc("/health", server.handleHealth)

	// Start server
	addr := fmt.Sprintf(":%s", config.ServerPort)
	log.Printf("Server starting on port %s", config.ServerPort)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}

// loadConfig loads configuration from environment variables
func loadConfig() (*Config, error) {
	// Load .env file if it exists
	_ = godotenv.Load()

	// Parse DB port
	dbPort, err := strconv.Atoi(getEnv("DB_PORT", "5432"))
	if err != nil {
		return nil, fmt.Errorf("invalid DB_PORT: %w", err)
	}

	config := &Config{
		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     dbPort,
		DBUser:     getEnv("DB_USER", "postgres"),
		DBPassword: getEnv("DB_PASSWORD", ""),
		DBName:     getEnv("DB_NAME", "postgres"),
		DBSSLMode:  getEnv("DB_SSLMODE", "disable"),
		ServerPort: getEnv("SERVER_PORT", "8080"),
	}

	// Validate required fields
	if config.DBPassword == "" {
		log.Println("Warning: DB_PASSWORD is not set")
	}

	return config, nil
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// connectDB establishes a connection to the database
func connectDB(config *Config) (*sql.DB, error) {
	// Build connection string
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.DBHost, config.DBPort, config.DBUser, config.DBPassword, config.DBName, config.DBSSLMode,
	)

	// Open database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("error opening database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	return db, nil
}

// handleCheckHash processes the hash check request
func (s *Server) handleCheckHash(w http.ResponseWriter, r *http.Request) {
	// Only allow POST requests
	if r.Method != http.MethodPost {
		s.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Hash == "" {
		s.sendError(w, "Hash is required", http.StatusBadRequest)
		return
	}

	// Log the request (optional)
	log.Printf("Received request - Algorithm: %s, Hash: %s", req.HashAlgorithm, req.Hash)

	// Check if hash exists in database
	user, found, err := s.findUserByEmail(req.Email, req.Code)
	if err != nil {
		log.Printf("Database error: %v", err)
		s.sendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Prepare response
	response := Response{
		UserFound: found,
		Hash:      req.Hash,
	}

	if found {
		if req.Hash == hashKeccak256(fmt.Sprintf("%s%s", user.Hash, user.Code)) {
			response.Success = true
			response.UserData = user
			response.Message = "Authorized"

			s.sendJSON(w, response, http.StatusOK)
			return
		}
	}

	// otherwise
	response.Success = false
	response.Message = "Unauthorized"
	s.sendJSON(w, response, http.StatusForbidden)

}

// findUserByHash searches for a user with the given hash
func (s *Server) findUserByEmail(email string, code string) (*User, bool, error) {
	query := `
		SELECT id, username, email, hash, salt, code, created_at 
		FROM users 
		WHERE email = $1 AND code = $2
		LIMIT 1
	`

	var user User
	var createdAt sql.NullString

	err := s.db.QueryRow(query, email, code).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Hash,
		&user.Salt,
		&user.Code,
		&createdAt,
	)

	if err == sql.ErrNoRows {
		return nil, false, nil
	}

	if err != nil {
		return nil, false, fmt.Errorf("error querying database: %w", err)
	}

	if createdAt.Valid {
		user.CreatedAt = createdAt.String
	}

	return &user, true, nil
}

// handleHealth returns the health status of the server
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Check database connection
	if err := s.db.Ping(); err != nil {
		s.sendError(w, "Database unhealthy", http.StatusServiceUnavailable)
		return
	}

	response := map[string]interface{}{
		"status":   "healthy",
		"database": "connected",
	}
	s.sendJSON(w, response, http.StatusOK)
}

// sendJSON sends a JSON response
func (s *Server) sendJSON(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// sendError sends an error response
func (s *Server) sendError(w http.ResponseWriter, message string, statusCode int) {
	response := Response{
		Success: false,
		Message: message,
	}
	s.sendJSON(w, response, statusCode)
}

// hashKeccak256 hashes a string using keccak256 and returns the hex string
func hashKeccak256(input string) string {
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(input))
	return hex.EncodeToString(hash.Sum(nil))
}
