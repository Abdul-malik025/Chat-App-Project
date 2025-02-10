const express = require("express");
const http = require("http");
const socketIo = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Serve static files from 'public' folder
app.use(express.static("public"));

// Listen for new connections
io.on("connection", (socket) => {
    console.log("A user connected");

    // Listen for chat messages from clients
    socket.on("chat message", (msg) => {
        io.emit("chat message", msg); // Broadcast message to all users
    });

    socket.on("disconnect", () => {
        console.log("User disconnected");
    });
});

// Start server
const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});