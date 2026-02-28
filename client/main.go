package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/sha3"
)

// RequestBody represents the JSON structure to send to the server
type RequestBody struct {
	Code          string `json:"code"`
	Hash          string `json:"hash"`
	Email         string `json:"email"`
	HashAlgorithm string `json:"hash_algorithm"`
}

// ServerResponse represents the response from the server
type ServerResponse struct {
	Success   bool        `json:"success"`
	Message   string      `json:"message"`
	UserFound bool        `json:"user_found,omitempty"`
	UserData  interface{} `json:"user_data,omitempty"`
	Hash      string      `json:"hash,omitempty"`
}

func main() {
	// Parse command line flags
	password := flag.String("password", "", "Password of user")
	email := flag.String("email", "", "Email of user")
	code := flag.String("code", "", "Temp code")
	salt := flag.String("salt", "", "Salt of password")
	serverURL := flag.String("server", "http://localhost:8080", "Server URL")
	timeout := flag.Int("timeout", 30, "Request timeout in seconds")

	flag.Parse()

	if *password == "" {
		fmt.Println("Error: -string flag is required")
		flag.Usage()
		os.Exit(1)
	}

	// Hash the string
	hash := hashKeccak256(fmt.Sprintf("%s%s", *password, *salt))
	hashedHash := hashKeccak256(fmt.Sprintf("%s%s", hash, *code))
	fmt.Printf("Original string: %s\n", *password)
	fmt.Printf("Keccak256 hash: %s\n", hash)
	txt := ""

	for i := 0; i < 100; i++ {
		start := time.Now()
		// Send to server
		err := sendToServer(*serverURL, *code, hashedHash, *email, *timeout)
		if err != nil {
			_, err := fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			if err != nil {
				return
			}

		}
		elapsed := time.Since(start).Microseconds()
		txt += fmt.Sprintf("%d\n", elapsed)
	}
	err := os.WriteFile("timing.log", []byte(txt), 0644)
	if err != nil {
		log.Fatal(err)
	}

	os.Exit(1)
}

// hashKeccak256 hashes a string using keccak256 and returns the hex string
func hashKeccak256(input string) string {
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(input))
	return hex.EncodeToString(hash.Sum(nil))
}

// sendToServer sends the hash to the server and processes the response
func sendToServer(serverURL, code string, hash string, email string, timeout int) error {
	// Prepare the request body
	requestBody := RequestBody{
		Code:          code,
		Hash:          hash,
		Email:         email,
		HashAlgorithm: "keccak256",
	}

	// Marshal to JSON
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %w", err)
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	// Create request
	url := fmt.Sprintf("%s/api/check-hash", serverURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Keccak256-Client/1.0")

	// Send request
	fmt.Printf("Sending hash to server: %s\n", url)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	// Parse response
	var serverResp ServerResponse
	if err := json.Unmarshal(body, &serverResp); err != nil {
		return fmt.Errorf("error parsing server response: %w\nRaw response: %s", err, string(body))
	}

	// Display results
	fmt.Println("\n=== Server Response ===")
	fmt.Printf("Success: %v\n", serverResp.Success)
	fmt.Printf("Message: %s\n", serverResp.Message)

	if serverResp.UserFound {
		fmt.Println("✅ User found in database!")
		if serverResp.UserData != nil {
			fmt.Printf("User data: %+v\n", serverResp.UserData)
		}
	} else {
		fmt.Println("❌ No user found with this hash")
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned error status: %d", resp.StatusCode)
	}

	return nil
}
