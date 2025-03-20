package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 trace trace.c

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/ringbuf"
)

type HealthResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type event struct {
	Filename [256]byte
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(HealthResponse{Status: "ok", Message: "Service is healthy"})
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var objs traceObjects
	if err := loadTraceObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	rawtp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.HandleExecveRawTp,
	})
	if err != nil {
		log.Fatalf("Attaching raw Tracepoint: %s", err)
	}
	defer rawtp.Close()

	rb, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to open ring buffer: %v", err)
	}
	defer rb.Close()

	go readEvents(rb)
	go startHealthServer()

	log.Println("Tracing execve syscalls...")
	time.Sleep(15 * time.Second)
}

func readEvents(rb *ringbuf.Reader) {
	var e event
	for {
		record, err := rb.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("Failed to parse event: %v", err)
			continue
		}
		fmt.Printf("Filename: %s\n", strings.TrimRight(string(e.Filename[:]), "\x00"))
	}
}

func startHealthServer() {
	http.HandleFunc("/healthz", healthHandler)
	port := "3377"
	log.Println("Health server running on localhost port " + port)
	if err := http.ListenAndServe("localhost:"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
