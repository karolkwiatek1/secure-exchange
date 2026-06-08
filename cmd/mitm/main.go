// Binary mitm runs a man-in-the-middle proxy used to demonstrate
// the system's resistance to server identity spoofing attacks.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/karolkwiatek1/secure-exchange/logger"
)

var (
	realServerURL string
	fakeServerID  string

	// interceptPaths lists endpoints where the proxy will modify the server_id
	interceptPaths = map[string]bool{
		"/request-file":      true,
		"/request-file-list": true,
	}
)

func modifyServerID(data []byte) []byte {
	var resp map[string]interface{}
	if err := json.Unmarshal(data, &resp); err != nil {
		return data
	}
	resp["server_id"] = fakeServerID
	modified, err := json.Marshal(resp)
	if err != nil {
		return data
	}
	return modified
}

func proxyHandler(log *logger.EventLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetURL := realServerURL + r.URL.Path

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		req, err := http.NewRequest(r.Method, targetURL, bytes.NewReader(body))
		if err != nil {
			log.Log("MITM", fmt.Sprintf("Request creation failed: %v", err))
			http.Error(w, "Proxy error", http.StatusBadGateway)
			return
		}
		req.Header = r.Header

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Log("MITM", fmt.Sprintf("Upstream error: %v", err))
			http.Error(w, "Upstream unreachable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "Failed to read upstream response", http.StatusInternalServerError)
			return
		}

		if interceptPaths[r.URL.Path] {
			originalBody := string(respBody)
			respBody = modifyServerID(respBody)
			if string(respBody) != originalBody {
				log.Log("MITM", fmt.Sprintf("INTERCEPTED %s: server_id spoofed to %s", r.URL.Path, fakeServerID))
			}
		}

		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
	}
}

func main() {
	log := logger.New(os.Stdout)

	realServerURL = os.Getenv("REAL_SERVER")
	if realServerURL == "" {
		realServerURL = "http://localhost:8282"
	}

	fakeServerID = os.Getenv("FAKE_SERVER_ID")
	if fakeServerID == "" {
		fakeServerID = "EVIL_SERVER_IMPERSONATOR"
	}

	log.Log("MITM", fmt.Sprintf("Evil proxy starting on :9393"))
	log.Log("MITM", fmt.Sprintf("Forwarding to real server: %s", realServerURL))
	log.Log("MITM", fmt.Sprintf("Fake server_id injected in responses: %s", fakeServerID))
	log.Log("MITM", "Waiting for victim connections...")

	mux := http.NewServeMux()
	mux.HandleFunc("/", proxyHandler(log))

	if err := http.ListenAndServe(":9393", mux); err != nil {
		log.Log("MITM", fmt.Sprintf("Failed to start: %v", err))
		os.Exit(1)
	}
}
