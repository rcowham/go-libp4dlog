package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/rcowham/go-libp4"
	"github.com/rs/cors"
)

type key int

const (
	requestIDKey key = 0
)

var (
	Version      string = ""
	GitTag       string = ""
	GitCommit    string = ""
	GitTreeState string = ""
	listenAddr   string
	healthy      int32
)

type p4mon struct {
	all    bool
	logger *log.Logger
}

func (p4c *p4mon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p4c.logger.Println("monitor invoked")
	p4 := p4.NewP4()
	result, err := p4.Run([]string{"monitor", "show"})
	if err != nil {
		p4c.logger.Printf("Error: %v %v\n", err, result)
	}
	msg := ""
	var id, status, user, ctime, command string
	for _, r := range result {
		if v, ok := r["id"]; ok {
			id = v.(string)
		}
		if v, ok := r["status"]; ok {
			status = v.(string)
		}
		if v, ok := r["user"]; ok {
			user = v.(string)
		}
		if v, ok := r["time"]; ok {
			ctime = v.(string)
		}
		if v, ok := r["command"]; ok {
			command = v.(string)
		}
		if !p4c.all && command != "IDLE" {
			msg += fmt.Sprintf("%-6s %s %-10s %s %s\n", id, status, user, ctime, command)
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, msg)
}

func main() {
	flag.StringVar(&listenAddr, "listen-addr", ":8001", "server listen address")
	flag.Parse()

	logger := log.New(os.Stdout, "http: ", log.LstdFlags)

	logger.Println("Simple go server")
	logger.Println("Version:", Version)
	logger.Println("GitTag:", GitTag)
	logger.Println("GitCommit:", GitCommit)
	logger.Println("GitTreeState:", GitTreeState)

	logger.Println("Server is starting...")

	mon := &p4mon{all: false, logger: logger}
	monAll := &p4mon{all: true, logger: logger}

	router := http.NewServeMux()
	router.Handle("/", index())
	router.Handle("/healthz", healthz())
	router.Handle("/metrics", metrics())
	router.Handle("/monitor", mon)
	router.Handle("/monitor_all", monAll)

	handler := cors.Default().Handler(router)

	nextRequestID := func() string {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      tracing(nextRequestID)(logging(logger)(handler)),
		ErrorLog:     logger,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	go func() {
		<-quit
		logger.Println("Server is shutting down...")
		atomic.StoreInt32(&healthy, 0)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		server.SetKeepAlivesEnabled(false)
		if err := server.Shutdown(ctx); err != nil {
			logger.Fatalf("Could not gracefully shutdown the server: %v\n", err)
		}
		close(done)
	}()

	logger.Println("Server is ready to handle requests at", listenAddr)
	atomic.StoreInt32(&healthy, 1)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("Could not listen on %s: %v\n", listenAddr, err)
	}

	<-done
	logger.Println("Server stopped")
}

func index() http.Handler {
	return cors.Default().Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Hello, World!")
	}))
}

func metrics() http.Handler {
	msg := `	Static Monitor Output
	323 I p4dtguser  00:00:05 IDLE
	1321 I p4dtguser  00:00:04 IDLE 
	1337 I p4dtguser  00:00:03 IDLE 
	1353 I p4dtguser  00:00:03 IDLE 
	1369 I p4dtguser  00:00:02 IDLE 
	1847 I swarm      00:04:36 IDLE 
	2123 B remote     193:06:33 ldapsync 
	3283 I p4dtguser  00:00:03 IDLE 
	3318 R rcowham    00:00:00 monitor 
   `
	return cors.Default().Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, msg)
	}))

}

func healthz() http.Handler {
	return cors.Default().Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&healthy) == 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
}

func logging(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				requestID, ok := r.Context().Value(requestIDKey).(string)
				if !ok {
					requestID = "unknown"
				}
				logger.Println(requestID, r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func tracing(nextRequestID func() string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-Id")
			if requestID == "" {
				requestID = nextRequestID()
			}
			ctx := context.WithValue(r.Context(), requestIDKey, requestID)
			w.Header().Set("X-Request-Id", requestID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
