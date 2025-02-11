const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// MySQL Database Connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",  
    password: "0556614768",  
    database: "chatapp",
});

db.connect((err) => {
    if (err) throw err;
    console.log("MySQL Connected...");
});

// Middleware to parse JSON bodies and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session setup
app.use(
    session({
        secret: "chatapp_secret",  // Change to a more secure secret
        resave: false,
        saveUninitialized: true,
    })
);

// Serve static files
app.use(express.static("public"));

// Registration endpoint
app.post("/register", (req, res) => {
    const { username, password } = req.body;
    
    // Hash the password before saving
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) throw err;
        
        const query = "INSERT INTO users (username, password) VALUES (?, ?)";
        db.query(query, [username, hashedPassword], (err, result) => {
            if (err) {
                res.status(500).send("Error registering user.");
                return;
            }
            res.status(200).send("Registration successful!");
        });
    });
});

// Login endpoint
app.post("/login", (req, res) => {
    const { username, password } = req.body;
    
    const query = "SELECT * FROM users WHERE username = ?";
    db.query(query, [username], (err, results) => {
        if (err || results.length === 0) {
            res.status(401).send("User not found.");
            return;
        }

        const user = results[0];

        // Compare the provided password with the stored hash
        bcrypt.compare(password, user.password, (err, match) => {
            if (err || !match) {
                res.status(401).send("Incorrect password.");
                return;
            }
            
            // Save user info in session
            req.session.user = { username: user.username };
            res.status(200).send("Login successful!");
            
            

            
        });
    });
});

// Serve chat history on user connection
io.on("connection", (socket) => {
    console.log("A user connected");

    // Send chat history from DB
    db.query("SELECT * FROM messages ORDER BY timestamp ASC", (err, results) => {
        if (err) throw err;
        socket.emit("chat history", results);
    });

    socket.on("chat message", (data) => {
        const { username, message } = data;

        // Save message to MySQL
        const query = "INSERT INTO messages (username, message) VALUES (?, ?)";
        db.query(query, [username, message], (err, result) => {
            if (err) throw err;
            io.emit("chat message", { username, message });
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