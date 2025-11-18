# About
This is a simple websocket server implementation from scratch.
I implemented this for my presentation about WebSocket in CS544 Computer Network 2 class.

# Usage
If you haven't installed Go yet, please download and install it from https://golang.org/dl/.
Or simply `brew install go` if you are using macOS with Homebrew.

Build and run the server
```
go build -o go-websocket
./go-websocket
```

Access http://localhost:8080 in your browser.
Open your browser console and run the following code to send and receive messages
```javascript

let ws = new WebSocket("ws://localhost:8080");

ws.onmessage = msg => console.log("Received:", msg.data);

ws.send("Hello, Server!");

// 270 bytes
ws.send("Hello, Server! Hello, Server! Hello, Server! Hello, Server! Hello, Server! Hello, Server! Hello, Server! Hello, Server! Hello, Server! Hello, Server! Hello, Server! Hello, Server! Hello, Server! Hello, Server! Hello, Server! Hello, Server! Hello, Server! Hello, Server! ");
```