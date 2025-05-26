package events

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// Event represents a workflow run event
type Event struct {
	Action      string `json:"action"`
	WorkflowRun struct {
		ID         int64  `json:"id"`
		Name       string `json:"name"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		HTMLURL    string `json:"html_url"`
	} `json:"workflow_run"`
}

// Manager handles SSE connections and event broadcasting
type Manager struct {
	clients    map[chan Event]bool
	register   chan chan Event
	unregister chan chan Event
	broadcast  chan Event
	mu         sync.Mutex
}

// NewManager creates a new event manager
func NewManager() *Manager {
	return &Manager{
		clients:    make(map[chan Event]bool),
		register:   make(chan chan Event),
		unregister: make(chan chan Event),
		broadcast:  make(chan Event),
	}
}

// Start begins the event manager's main loop
func (m *Manager) Start() {
	for {
		select {
		case client := <-m.register:
			m.mu.Lock()
			m.clients[client] = true
			m.mu.Unlock()
		case client := <-m.unregister:
			m.mu.Lock()
			if _, ok := m.clients[client]; ok {
				delete(m.clients, client)
				close(client)
			}
			m.mu.Unlock()
		case event := <-m.broadcast:
			m.mu.Lock()
			for client := range m.clients {
				select {
				case client <- event:
				default:
					close(client)
					delete(m.clients, client)
				}
			}
			m.mu.Unlock()
		}
	}
}

// HandleSSE handles SSE connections
func (m *Manager) HandleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

	// Create a channel for this client
	client := make(chan Event, 1)
	m.register <- client

	// Ensure client is removed when connection closes
	defer func() {
		m.unregister <- client
	}()

	// Send initial connection message
	fmt.Fprintf(w, "data: %s\n\n", "Connected")
	flusher.Flush()

	// Keep connection alive with periodic heartbeats
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Keep connection alive and send events
	for {
		select {
		case event := <-client:
			data, err := json.Marshal(event)
			if err != nil {
				log.Printf("Error marshaling event: %v", err)
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			// Send heartbeat to keep connection alive
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// HandleWebhook processes GitHub webhook events
func (m *Manager) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var event Event
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Broadcast the event to all connected clients
	m.broadcast <- event

	w.WriteHeader(http.StatusOK)
}
