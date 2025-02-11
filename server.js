const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const session = require("express-session");
//const MySQLStore = require("express-mysql-session")(session);  Optional: use for production 

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Use environment variables for configuration (with defaults)
const SESSION_SECRET = process.env.SESSION_SECRET || "chatapp_secret";
const DB_HOST = process.env.DB_HOST || "localhost";
const DB_USER = process.env.DB_USER || "root";
const DB_PASSWORD = process.env.DB_PASSWORD || "";
const DB_DATABASE = process.env.DB_DATABASE || "chatapp";

// MySQL Database Connection
const db = mysql.createConnection({
    host: DB_HOST,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_DATABASE,
});

db.connect((err) => {
    if (err) {
        console.error("MySQL connection error: ", err);
        process.exit(1);
    }
    console.log("MySQL Connected...");
});

/* Optional: Use a MySQL session store for production
const sessionStore = new MySQLStore({}, db.promise());
 */


// Middleware to parse JSON bodies and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session setup
app.use(
    session({
        key: "chatapp_session",
        secret: SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
     // store: sessionStore,  Comment out if you don't want to use a session store
        cookie: { 
            secure: false, // Set to true if using HTTPS
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        },
    })
);

// Serve static files from the "public" directory
app.use(express.static("public"));

// Registration endpoint
app.post("/register", (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: "Username and password are required." });
    }
    
    // Check if the username already exists
    const checkQuery = "SELECT * FROM users WHERE username = ?";
    db.query(checkQuery, [username], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: "Database error." });
        }
        if (results.length > 0) {
            return res.status(409).json({ message: "Username already exists." });
        }
        
        // Hash the password before saving
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: "Error processing password." });
            }
            
            const query = "INSERT INTO users (username, password) VALUES (?, ?)";
            db.query(query, [username, hashedPassword], (err, result) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ message: "Error registering user." });
                }
                return res.status(200).json({ message: "Registration successful!" });
            });
        });
    });
});

// Login endpoint
app.post("/login", (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: "Username and password are required." });
    }
    
    const query = "SELECT * FROM users WHERE username = ?";
    db.query(query, [username], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: "Database error." });
        }
        if (results.length === 0) {
            return res.status(401).json({ message: "User not found." });
        }

        const user = results[0];
        // Compare the provided password with the stored hash
        bcrypt.compare(password, user.password, (err, match) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: "Error comparing passwords." });
            }
            if (!match) {
                return res.status(401).json({ message: "Incorrect password." });
            }
            
            // Save user info in session
            req.session.user = { username: user.username };
            return res.status(200).json({ message: "Login successful!", username: user.username });
        });
    });
});

// Socket.IO handling
io.on("connection", (socket) => {
    console.log("A user connected");

    // Send chat history from the database
    db.query("SELECT * FROM messages ORDER BY timestamp ASC", (err, results) => {
        if (err) {
            console.error("Error fetching chat history: ", err);
            return;
        }
        socket.emit("chat history", results);
    });

    socket.on("chat message", (data) => {
        const { username, message } = data;
        if (!username || !message) return; // Basic validation

        // Save message to MySQL
        const query = "INSERT INTO messages (username, message) VALUES (?, ?)";
        db.query(query, [username, message], (err, result) => {
            if (err) {
                console.error("Error saving message: ", err);
                return;
            }
            io.emit("chat message", { username, message });
        });
    });

    socket.on("disconnect", () => {
        console.log("User disconnected");
    });
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
