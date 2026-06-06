package relay

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/mycodex/mycodex-relay/internal/config"
)

type Server struct {
	config config.Config
	mux    *http.ServeMux
}

func NewServer(cfg config.Config) *Server {
	server := &Server{config: cfg, mux: http.NewServeMux()}
	server.mux.HandleFunc("/health", server.handleHealth)
	server.mux.HandleFunc("/v1/ws", server.handleWebSocket)
	return server
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) Serve(ctx context.Context) error {
	address := net.JoinHostPort(s.config.ListenHost, fmt.Sprintf("%d", s.config.ListenPort))
	httpServer := &http.Server{Addr: address, Handler: s.Handler()}
	go func() {
		<-ctx.Done()
		httpServer.Shutdown(context.Background())
	}()
	err := httpServer.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{\"status\":\"ok\"}\n"))
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "websocket endpoint requires session command", http.StatusBadRequest)
}
