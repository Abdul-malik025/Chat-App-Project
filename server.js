const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const mysql = require("mysql2");

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// MySQL Database Connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",  // Change if needed
    password: "",  // Add your password
    database: "chatapp",
});

db.connect((err) => {
    if (err) throw err;
    console.log("MySQL Connected...");
});

// Serve static files from 'public' folder
app.use(express.static("public"));

// Load chat history on user connection
io.on("connection", (socket) => {
    console.log("A user connected");

    // Fetch chat history from the database
    db.query("SELECT * FROM messages ORDER BY timestamp ASC", (err, results) => {
        if (err) throw err;
        socket.emit("chat history", results);
    });

    // Listen for chat messages
    socket.on("chat message", (data) => {
        const { username, message } = data;

        // Save message to MySQL
        const query = "INSERT INTO messages (username, message) VALUES (?, ?)";
        db.query(query, [username, message], (err, result) => {
            if (err) throw err;
            io.emit("chat message", { username, message }); // Broadcast message
        });
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