package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 trace trace.c

import (
	"log"
	"time"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"net/http"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/ringbuf"
)

type HealthResponse struct {
        Status  string `json:"status"`
        Message string `json:"message"`
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	// Set response type to JSON
	w.Header().Set("Content-Type", "application/json")

	// Create the health response
	response := HealthResponse{
		Status:  "ok",
		Message: "Service is healthy",
	}

	// Send the JSON response
	json.NewEncoder(w).Encode(response)
}

// Define the event structure matching the eBPF struct
type event struct {
	Filename  [256]byte
}

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs traceObjects
	if err := loadTraceObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()
	
	// Attach Raw Tracepoint
	rawtp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name: "sys_enter", 
		Program: objs.HandleExecveRawTp,
	})
	if err != nil {
		log.Fatalf("Attaching raw Tracepoint: %s", err)
	}
	defer rawtp.Close()

	// Open ring buffer to read events
	rb, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to open ring buffer: %v", err)
	}
	defer rb.Close()

	go func() {
		var e event
		for {
			record, err := rb.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				//log.Printf("Error reading ring buffer: %v", err)
				continue
			}

			// Parse binary data into event struct
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("Failed to parse event: %v", err)
				continue
			}
			filename := strings.TrimRight(string(e.Filename[:]), "\x00")
			fmt.Printf("Filename: %s\n", filename)
		}
	}()

	// Start the healthcheck HTTP endpoint
	go func() {
		http.HandleFunc("/healthz", healthHandler)

		port := "3377"
		log.Println("Health server running on localhost port " + port)
		if err := http.ListenAndServe("localhost:"+port, nil); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	log.Println("Tracing execve syscalls...")
	time.Sleep(time.Second * 15)
}
