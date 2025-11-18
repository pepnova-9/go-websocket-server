package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

/* ------The WebSockets Frame -----
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-------+-+-------------+-------------------------------+
   |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
   |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
   |N|V|V|V|       |S|             |   (if payload len==126/127)   |
   | |1|2|3|       |K|             |                               |
   +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
   |     Extended payload length continued, if payload len == 127  |
   + - - - - - - - - - - - - - - - +-------------------------------+
   |                               |Masking-key, if MASK set to 1  |
   +-------------------------------+-------------------------------+
   | Masking-key (continued)       |          Payload Data         |
   +-------------------------------- - - - - - - - - - - - - - - - +
   :                     Payload Data continued ...                :
   + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
   |                     Payload Data continued ...                |
   +---------------------------------------------------------------+

*/

// the websockets opcodes
const (
	opCont  = 0x0 // 0000
	opText  = 0x1 // 0001
	opBin   = 0x2 // 0010
	opClose = 0x8 // 1000
	opPing  = 0x9 // 1001
	opPong  = 0xA // 1010
)

// WebSocket GUID used when computing Sec-WebSocket-Accept during the handshake
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// frame represents a single WebSocket frame.
// Fin: true if this frame completes the message (FIN bit)
// Opcode: identifies text/binary/control/ping pong frame types
// Payload: decoded message bytes
type frame struct {
	Fin     bool
	Opcode  byte
	Payload []byte
}

// large buffer may have one or more websocket frames
// parseFrames walks the incoming buffer, extracting as many complete frames as
// possible. Any leftover bytes (partial frame) are returned so the caller can
// prepend them to the next read.
func parseFrames(buffer []byte) ([]frame, []byte, error) {
	var frames []frame
	offset := 0

	// we loop through the buffer data arrived and capture frames
	// one "Read" can give us multiple frames

	// if we have at least 2 bytes, there might be a complete frame to parse
	// Remember: the minimum frame size is 2 bytes (no payload, no mask)
	for len(buffer)-offset >= 2 {
		firstByte := buffer[offset]    // first byte (FIN(1bit) + RSV(3bit) + Opcode(4bit))
		fin := (firstByte & 0x80) != 0 // the fin bit is the first bit      (1000,0000)
		opcode := firstByte & 0x0F     // the opcodes are the last 4 bits   (0000,1111)

		secondByte := buffer[offset+1]     // second byte (MASK(1bit) + Payload len(7bit))
		masked := (secondByte & 0x80) != 0 // the mask bit is the first bit     (1000,0000)
		length := int(secondByte & 0x7F)   // the length is the last 7 bits     (0111,1111)
		pos := offset + 2

		if length == 126 {
			// Length 126 means the next 2 bytes (extended payload len) contain the actual payload length
			if len(buffer)-pos < 2 {
				break
			}
			length = int(binary.BigEndian.Uint16(buffer[pos : pos+2]))
			pos += 2
		} else if length == 127 {
			// Length 127 means the next 8 bytes (extended payload len + continue) hold the payload length
			if len(buffer)-pos < 8 {
				break
			}
			hi := binary.BigEndian.Uint32(buffer[pos : pos+4])
			lo := binary.BigEndian.Uint32(buffer[pos+4 : pos+8])
			pos += 8
			if hi != 0 {
				return nil, nil, errors.New("frame larger than 4GB not supported")
			}
			length = int(lo)
		}

		var maskKey []byte
		if masked {
			// Client-to-server frames must include a 4-byte masking key
			if len(buffer)-pos < 4 {
				break
			}
			maskKey = buffer[pos : pos+4]
			pos += 4
		}

		if len(buffer)-pos < length {
			break // incomplete payload
		}

		payload := make([]byte, length)
		copy(payload, buffer[pos:pos+length])

		if masked {
			for i := 0; i < length; i++ {
				payload[i] ^= maskKey[i%4]
			}
		}

		frames = append(frames, frame{Fin: fin, Opcode: opcode, Payload: payload})
		offset = pos + length
	}

	// return complete frames and any leftover bytes belong to a partial frame
	return frames, buffer[offset:], nil
}

// building a frame so we can send it to the client
// buildFrame assembles the header for a server-to-client frame (no masking)
// The header length expands to 2, 4, or 10 bytes depending on payload size
func buildFrame(opcode byte, payload []byte, fin bool) []byte {
	firstByte := byte(0)
	if fin {
		firstByte = 0x80 // 1000 0000
	}
	firstByte |= opcode & 0x0F // 0000 1111

	length := len(payload)

	switch {
	// payload len is less than 126
	// header size is 2 bytes
	case length < 126:
		header := []byte{firstByte, byte(length)}
		return append(header, payload...)
	// payload len is less than or equal to 65535
	// header size is 4 bytes
	case length <= 0xFFFF:
		header := make([]byte, 4)
		header[0] = firstByte
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:], uint16(length))
		return append(header, payload...)
	// payload len is greater than 65535
	// header size is 10 bytes
	default:
		header := make([]byte, 10)
		header[0] = firstByte
		header[1] = 127
		binary.BigEndian.PutUint32(header[2:], 0)
		binary.BigEndian.PutUint32(header[6:], uint32(length))
		return append(header, payload...)
	}
}

func startServer(addr string) (*http.Server, string, error) {
	// Start an HTTP/1.1 server and upgrade only WebSocket requests
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Reject normal HTTP traffic, only the WebSocket upgrade path is supported
		if strings.ToLower(r.Header.Get("Upgrade")) != "websocket" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("Use WebSocket upgrade"))
			return
		}
		// Check that the Connection header includes "Upgrade" (may contain multiple values)
		connection := strings.ToLower(r.Header.Get("Connection"))
		hasUpgrade := false
		for _, part := range strings.Split(connection, ",") {
			if strings.TrimSpace(part) == "upgrade" {
				hasUpgrade = true
				break
			}
		}

		// Validate standard handshake requirements (Sec-WebSocket-Key, version 13)
		key := r.Header.Get("Sec-WebSocket-Key")
		version := r.Header.Get("Sec-WebSocket-Version")
		if !hasUpgrade || key == "" || version != "13" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Hijack the underlying TCP connection so we can speak raw WebSocket frames
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Websocket upgrade not supported", http.StatusInternalServerError)
			return
		}

		// Switch to raw TCP socket so we can speak WebSocket
		conn, rw, err := hj.Hijack()
		if err != nil {
			http.Error(w, "Hijack failed", http.StatusInternalServerError)
			return
		}

		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}

		// Compute Sec-WebSocket-Accept (Sec-WebSocket-Key + GUID -> SHA-1 -> Base64)
		accept := sha1.Sum([]byte(key + wsGUID))
		acceptKey := base64.StdEncoding.EncodeToString(accept[:])

		// Send the mandatory upgrade response headers followed by a blank line
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
		_, _ = rw.WriteString("Upgrade: websocket\r\n")
		_, _ = rw.WriteString("Connection: Upgrade\r\n")
		_, _ = rw.WriteString(fmt.Sprintf("Sec-WebSocket-Accept: %s\r\n\r\n", acceptKey))
		if err := rw.Flush(); err != nil {
			_ = conn.Close()
			return
		}

		// From here on we operate on the raw TCP connection with WebSocket frames
		go handleConnection(conn, rw.Reader)
	})

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", err
	}

	server := &http.Server{Handler: mux}
	actualAddr := listener.Addr().String()

	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server error: %v", err)
		}
	}()

	return server, actualAddr, nil
}

// handleConnection processes the raw TCP socket after the upgrade
// It parses incoming WebSocket frames and responds based on the opcode
func handleConnection(conn net.Conn, reader *bufio.Reader) {
	// Ensure the TCP connection gets closed when the handler returns
	defer conn.Close()

	leftover := make([]byte, 0)
	buffer := make([]byte, 4096)
	var textBuf []byte // Accumulates pieces of fragmented text messages

	// send builds a single-frame message (FIN=true) and writes it to the connection
	send := func(opcode byte, payload []byte) error {
		frameData := buildFrame(opcode, payload, true)
		_, err := conn.Write(frameData)
		return err
	}

	// sendClose sends a CLOSE control frame with an optional reason, then returns
	sendClose := func(code uint16, reason string) {
		// build payload: 2-byte close code followed by optional text reason
		payload := make([]byte, 2+len(reason))
		binary.BigEndian.PutUint16(payload, code)
		// append reason bytes after the 2-byte code
		copy(payload[2:], reason)
		_ = send(opClose, payload)
	}

	for {
		/*
				messages coming from clients
				|          msg1         |         msg2         |         msg3         |
				      prev leftover|-----------------------------n| next leftover
			                                       buffer
		*/
		// bufio.Reader.Read delivers arbitrary chunks, not aligned to frame boundaries
		n, err := reader.Read(buffer)
		if n > 0 {
			chunk := buffer[:n]
			// prev leftover + new chunk
			leftover = append(leftover, chunk...)

			// parseFrames may return zero, one, or many frames along with leftovers
			frames, rest, perr := parseFrames(leftover)
			if perr != nil {
				// error → reply with CLOSE (1002) and terminate
				sendClose(1002, "protocol error")
				return
			}
			leftover = rest // Keep any partial frame bytes for the next read

			// Dispatch each frame based on opcode
			for _, f := range frames {
				switch f.Opcode {
				case opText:
					// This server just send back what it received (echo)
					// Same payload, same opcode
					if textBuf == nil {
						textBuf = make([]byte, 0, len(f.Payload))
					}
					textBuf = append(textBuf, f.Payload...)
					if f.Fin {
						msg := string(textBuf)
						log.Printf("[client TEXT] %s", msg)
						if err := send(opText, []byte(msg)); err != nil {
							return
						}
						textBuf = nil
					}
				case opBin:
					log.Printf("[client BIN] %d bytes", len(f.Payload))
					if err := send(opBin, f.Payload); err != nil {
						return
					}
				case opCont:
					// The WebSocket is fragmented, accumulate pieces until FIN=true
					if textBuf == nil {
						textBuf = make([]byte, 0)
					}
					textBuf = append(textBuf, f.Payload...)
					if f.Fin {
						msg := string(textBuf)
						log.Printf("[client TEXT] %s", msg)
						if err := send(opText, []byte(msg)); err != nil {
							return
						}
						textBuf = nil
					}
				case opPing:
					// Echo back a PONG with the same payload
					if err := send(opPong, f.Payload); err != nil {
						return
					}
				case opClose:
					// Reply with CLOSE and then terminate the connection
					_ = send(opClose, f.Payload)
					return
				default:
					// Unknown opcodes are ignored
				}
			}
		}

		if err != nil {
			if err != io.EOF {
				log.Printf("read error: %v", err)
			}
			return
		}
	}
}

func main() {
	const port = 8080
	addr := fmt.Sprintf(":%d", port)
	server, actualAddr, err := startServer(addr)
	if err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
	host := actualAddr
	if strings.HasPrefix(actualAddr, ":") {
		host = "localhost" + actualAddr
	}
	log.Printf("HTTP/1.1 WS server on ws://%s", host)
	// select {} blocks forever so the server keeps running
	select {}
	_ = server
}
