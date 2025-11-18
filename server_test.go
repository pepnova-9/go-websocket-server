package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func dialWebSocket(t *testing.T, addr string, path string) (net.Conn, *bufio.Reader) {
	t.Helper()
	u := url.URL{Scheme: "ws", Host: addr, Path: path}

	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}

	key := "w3CJHMbDL2EzLkh9GBhXDw=="
	req := fmt.Sprintf("GET %s HTTP/1.1\r\n", u.RequestURI()) +
		fmt.Sprintf("Host: %s\r\n", u.Host) +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		fmt.Sprintf("Sec-WebSocket-Key: %s\r\n", key) +
		"Sec-WebSocket-Version: 13\r\n\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("failed to send handshake: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("unexpected status: %s", resp.Status)
	}

	accept := strings.TrimSpace(resp.Header.Get("Sec-WebSocket-Accept"))
	sum := sha1.Sum([]byte(key + wsGUID))
	expectedAccept := base64.StdEncoding.EncodeToString(sum[:])
	if accept != expectedAccept {
		t.Fatalf("unexpected accept header: %s", accept)
	}

	return conn, reader
}

func TestWebSocketEcho(t *testing.T) {
	server, addr, err := startServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Close()

	time.Sleep(100 * time.Millisecond)

	conn, reader := dialWebSocket(t, addr, "/")
	defer conn.Close()

	sendText := func(msg string) {
		payload := []byte(msg)
		frame := buildFrame(opText, payload, true)
		if _, err := conn.Write(frame); err != nil {
			t.Fatalf("failed to send frame: %v", err)
		}
	}

	readFrame := func() frame {
		buf := make([]byte, 4096)
		//conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := reader.Read(buf)
		if err != nil {
			t.Fatalf("failed to read frame: %v", err)
		}
		frames, _, err := parseFrames(buf[:n])
		if err != nil {
			t.Fatalf("failed to parse frame: %v", err)
		}
		if len(frames) == 0 {
			t.Fatalf("no frame parsed")
		}
		return frames[0]
	}

	sendText("hello")
	f := readFrame()
	if f.Opcode != opText || string(f.Payload) != "hello" {
		t.Fatalf("unexpected response: opcode=%d payload=%s", f.Opcode, f.Payload)
	}

	sendText(strings.Repeat("a", 200))
	f = readFrame()
	if f.Opcode != opText || len(f.Payload) != 200 {
		t.Fatalf("unexpected response length: %d", len(f.Payload))
	}
}

func TestPingPong(t *testing.T) {
	server, addr, err := startServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Close()

	time.Sleep(100 * time.Millisecond)

	conn, reader := dialWebSocket(t, addr, "/")
	defer conn.Close()

	payload := []byte("ping")
	frame := buildFrame(opPing, payload, true)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("failed to send ping: %v", err)
	}

	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatalf("failed to read frame: %v", err)
	}
	frames, _, err := parseFrames(buf[:n])
	if err != nil {
		t.Fatalf("failed to parse frame: %v", err)
	}
	if len(frames) == 0 {
		t.Fatalf("no frame parsed")
	}
	f := frames[0]
	if f.Opcode != opPong || string(f.Payload) != "ping" {
		t.Fatalf("unexpected pong: opcode=%d payload=%s", f.Opcode, f.Payload)
	}
}
