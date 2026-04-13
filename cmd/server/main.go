package main

import (
	"fmt"
	"net/http"
	"os"

	"secure-exchange/logger"
	"secure-exchange/node"
)

func setupRouter(node *node.Node, log *logger.EventLogger) *http.ServeMux {
	mux := http.NewServeMux()

	// placeholder endpoint
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		log.Log("HTTP_SERVER", "Received download request from "+r.RemoteAddr)
		// todo: implement authentication via ttp and aes encryption
		w.Write([]byte("serwer wstal i ma certyfikat, transfer bedzie pozniej"))
	})

	return mux
}

func main() {
	log := logger.New(os.Stdout)
	log.Log("SYSTEM", "Booting up File Server Node...")

	// Initialize the Server Node (points to TTP on localhost:8181)
	serverNode, err := node.NewNode("Secure_File_Server_1", node.TypeServer, "http://localhost:8181", log)

	if err != nil {
		log.Log("FATAL", fmt.Sprintf("Failed to initialize server node: %v", err))
		os.Exit(1)
	}

	// Register and obtain certificate
	err = serverNode.RegisterAtTTP()
	if err != nil {
		log.Log("FATAL", fmt.Sprintf("Registration at TTP failed. Maybe check if TTP is running? Error: %v", err))
		os.Exit(1)
	}

	// Setup HTTP server for incoming requests
	mux := setupRouter(serverNode, log)

	// Start listening
	port := ":8282"
	log.Log("HTTP_SERVER", "File Server ready and listening on port "+port)

	if err := http.ListenAndServe(port, mux); err != nil {
		log.Log("FATAL", fmt.Sprintf("Server crashed: %v", err))
		os.Exit(1)
	}
}
