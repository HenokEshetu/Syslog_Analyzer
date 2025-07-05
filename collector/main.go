package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

type SyslogMessage struct {
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname"`
	Tag       string    `json:"tag"`
	Message   string    `json:"message"`
	Priority  int       `json:"priority"`
	SourceIP  string    `json:"source_ip"`
}

func main() {
	// Get NATS URL from environment
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://nats:4222"
	}

	// Connect to NATS
	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Fatalf("Error connecting to NATS: %v", err)
	}
	defer nc.Close()

	// Start UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", ":514")
	if err != nil {
		log.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer udpConn.Close()

	// Start TCP listener
	tcpAddr, err := net.ResolveTCPAddr("tcp", ":514")
	if err != nil {
		log.Fatal(err)
	}
	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer tcpListener.Close()

	log.Println("Syslog collector started on UDP and TCP port 514")

	// Handle UDP connections
	go handleUDP(udpConn, nc)

	// Handle TCP connections
	for {
		conn, err := tcpListener.Accept()
		if err != nil {
			log.Println("TCP accept error: ", err)
			continue
		}
		go handleTCP(conn, nc)
	}
}

func handleUDP(conn *net.UDPConn, nc *nats.Conn) {
	buffer := make([]byte, 8192)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Println("UDP read error: ", err)
			continue
		}
		processMessage(string(buffer[:n]), addr.IP.String(), nc)
	}
}

func handleTCP(conn net.Conn, nc *nats.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			log.Println("TCP read error: ", err)
			return
		}
		processMessage(strings.TrimSpace(message), conn.RemoteAddr().String(), nc)
	}
}

func processMessage(msg, sourceIP string, nc *nats.Conn) {
	// Parse syslog message (simplified)
	parts := strings.SplitN(msg, " ", 5)
	if len(parts) < 5 {
		log.Printf("Invalid syslog message: %s", msg)
		return
	}

	priority := 0
	timestamp, err := time.Parse(time.RFC3339, parts[0])
	if err != nil {
		timestamp = time.Now().UTC()
	}

	syslogMsg := SyslogMessage{
		Timestamp: timestamp,
		Hostname:  parts[1],
		Tag:       parts[2],
		Message:   strings.Join(parts[4:], " "),
		Priority:  priority,
		SourceIP:  sourceIP,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(syslogMsg)
	if err != nil {
		log.Printf("JSON marshal error: %v", err)
		return
	}

	// Publish to NATS
	if err := nc.Publish("syslog.raw", jsonData); err != nil {
		log.Printf("NATS publish error: %v", err)
	}
}
