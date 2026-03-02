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
	"sync"
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
	isParallel := flag.Int("isparallel", 0, "Send requests in parallel (1) or sequentially (0)")

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
	if *isParallel == 1 {
		// Prepare all requests upfront
		url := fmt.Sprintf("%s/api/check-hash", *serverURL)
		client := &http.Client{
			Timeout: time.Duration(*timeout) * time.Second,
		}
		requests := make([]*http.Request, 1000)
		for i := 0; i < 1000; i++ {
			req, err := prepareRequest(url, *code, hashedHash, *email)
			if err != nil {
				log.Fatalf("Error preparing request %d: %v", i, err)
			}
			requests[i] = req
		}

		// All requests ready — start the timer and fire them all at once
		var wg sync.WaitGroup
		gate := make(chan struct{})
		for i := 0; i < 1000; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-gate
				err := executeRequest(client, requests[idx])
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error (request %d): %v\n", idx, err)
				}
			}(i)
		}

		start := time.Now()
		close(gate) // release all goroutines at once
		wg.Wait()

		elapsed := time.Since(start).Microseconds()
		txt := fmt.Sprintf("%d\n", elapsed)
		err := os.WriteFile("timing2.log", []byte(txt), 0644)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		txt := ""
		for i := 0; i < 1000; i++ {
			start := time.Now()
			err := sendToServer(*serverURL, *code, hashedHash, *email, *timeout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			}
			elapsed := time.Since(start).Microseconds()
			txt += fmt.Sprintf("%d\n", elapsed)
		}
		err := os.WriteFile("timing.log", []byte(txt), 0644)
		if err != nil {
			log.Fatal(err)
		}
	}

	os.Exit(1)
}

// hashKeccak256 hashes a string using keccak256 and returns the hex string
func hashKeccak256(input string) string {
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(input))
	return hex.EncodeToString(hash.Sum(nil))
}

// prepareRequest builds an HTTP request ready to be sent
func prepareRequest(url, code, hash, email string) (*http.Request, error) {
	requestBody := RequestBody{
		Code:          code,
		Hash:          hash,
		Email:         email,
		HashAlgorithm: "keccak256",
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("error marshaling JSON: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Keccak256-Client/1.0")

	return req, nil
}

// executeRequest sends a prepared request and processes the response
func executeRequest(client *http.Client, req *http.Request) error {
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	var serverResp ServerResponse
	if err := json.Unmarshal(body, &serverResp); err != nil {
		return fmt.Errorf("error parsing server response: %w\nRaw response: %s", err, string(body))
	}

	fmt.Println("\n=== Server Response ===")
	fmt.Printf("Success: %v\n", serverResp.Success)
	fmt.Printf("Message: %s\n", serverResp.Message)

	if serverResp.UserFound {
		fmt.Println("User found in database!")
		if serverResp.UserData != nil {
			fmt.Printf("User data: %+v\n", serverResp.UserData)
		}
	} else {
		fmt.Println("No user found with this hash")
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned error status: %d", resp.StatusCode)
	}

	return nil
}

// sendToServer sends the hash to the server and processes the response
func sendToServer(serverURL, code string, hash string, email string, timeout int) error {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	url := fmt.Sprintf("%s/api/check-hash", serverURL)
	req, err := prepareRequest(url, code, hash, email)
	if err != nil {
		return err
	}

	return executeRequest(client, req)
}
