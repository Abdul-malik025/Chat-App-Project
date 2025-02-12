const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const session = require("express-session");
//const MySQLStore = require("express-mysql-session")(session);
const multer = require("multer");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Environment configuration (or use process.env)
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
db.connect(err => {
  if (err) {
    console.error("MySQL connection error:", err);
    process.exit(1);
  }
  console.log("MySQL Connected...");
});

//  MySQL session store
//const sessionStore = new MySQLStore({}, db.promise());

// Middleware for parsing JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session setup
app.use(
  session({
    key: "chatapp_session",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    //store: sessionStore,
    cookie: {
      secure: false, // set to true if using HTTPS
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    },
  })
);

// Serve static files from the public directory
app.use(express.static("public"));

/* ---------------------------
   FILE UPLOAD SETUP (Multer)
---------------------------- */
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "public/uploads/");
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + "-" + uniqueSuffix + ext);
  },
});
const upload = multer({ storage: storage });

// File upload endpoint
app.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: "No file uploaded." });
  }
  const fileUrl = `/uploads/${req.file.filename}`;
  let mediaType = "";
  if (req.file.mimetype.startsWith("image/")) {
    mediaType = "image";
  } else if (req.file.mimetype.startsWith("video/")) {
    mediaType = "video";
  } else {
    mediaType = "file";
  }
  return res.status(200).json({ message: "File uploaded successfully!", fileUrl, mediaType });
});

/* ---------------------------
   AUTHENTICATION ENDPOINTS
---------------------------- */
// Registration endpoint
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: "Username and password are required." });
  
  const checkQuery = "SELECT * FROM users WHERE username = ?";
  db.query(checkQuery, [username], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Database error." });
    }
    if (results.length > 0) {
      return res.status(409).json({ message: "Username already exists." });
    }
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
  if (!username || !password)
    return res.status(400).json({ message: "Username and password are required." });
  
  const query = "SELECT * FROM users WHERE username = ?";
  db.query(query, [username], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Database error." });
    }
    if (results.length === 0)
      return res.status(401).json({ message: "User not found." });
    const user = results[0];
    bcrypt.compare(password, user.password, (err, match) => {
      if (err || !match)
        return res.status(401).json({ message: "Incorrect password." });
      req.session.user = { username: user.username };
      return res.status(200).json({ message: "Login successful!", username: user.username });
    });
  });
});

// Logout endpoint
app.post("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).json({ message: "Logout error." });
    }
    res.clearCookie("chatapp_session");
    return res.status(200).json({ message: "Logged out successfully!" });
  });
});

// Check session endpoint
app.get("/me", (req, res) => {
  if (req.session.user)
    return res.status(200).json({ loggedIn: true, user: req.session.user });
  return res.status(200).json({ loggedIn: false });
});

/* ---------------------------
         ROOM ENDPOINTS
---------------------------- */
// List available rooms
app.get("/rooms", (req, res) => {
  const query = "SELECT room_name FROM rooms";
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Error fetching rooms." });
    }
    const rooms = results.map(row => row.room_name);
    res.status(200).json({ rooms });
  });
});

// Create a new room
app.post("/rooms", (req, res) => {
  const { room_name } = req.body;
  if (!room_name)
    return res.status(400).json({ message: "Room name is required." });
  
  const checkQuery = "SELECT * FROM rooms WHERE room_name = ?";
  db.query(checkQuery, [room_name], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Database error." });
    }
    if (results.length > 0)
      return res.status(409).json({ message: "Room already exists." });
    
    const created_by = req.session && req.session.user ? req.session.user.username : "anonymous";
    const query = "INSERT INTO rooms (room_name, created_by) VALUES (?, ?)";
    db.query(query, [room_name, created_by], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "Error creating room." });
      }
      res.status(200).json({ message: "Room created successfully!", room_name });
    });
  });
});

/* ---------------------------
       SOCKET.IO HANDLING
---------------------------- */
io.on("connection", socket => {
  console.log("A user connected: " + socket.id);

  // When a user joins a room
  socket.on("join room", roomName => {
    socket.join(roomName);
    console.log(`Socket ${socket.id} joined room: ${roomName}`);
    socket.emit("joined room", roomName);
    const query = "SELECT * FROM messages WHERE room = ? ORDER BY timestamp ASC";
    db.query(query, [roomName], (err, results) => {
      if (err) {
        console.error("Error fetching chat history for room:", err);
        return;
      }
      socket.emit("chat history", results);
    });
  });

  // Handle incoming chat messages
  socket.on("chat message", data => {
    const { username, message, room, media, mediaType } = data;
    // Either text or media must be provided.
    if (!username || (!message && !media) || !room) return;
    if (media) {
      const query =
        "INSERT INTO messages (room, username, message, media, mediaType) VALUES (?, ?, ?, ?, ?)";
      db.query(query, [room, username, message || "", media, mediaType], (err, result) => {
        if (err) {
          console.error("Error saving media message:", err);
          return;
        }
        io.to(room).emit("chat message", { username, message, media, mediaType });
      });
    } else {
      const query = "INSERT INTO messages (room, username, message) VALUES (?, ?, ?)";
      db.query(query, [room, username, message], (err, result) => {
        if (err) {
          console.error("Error saving message:", err);
          return;
        }
        io.to(room).emit("chat message", { username, message });
      });
    }
  });

  socket.on("disconnect", () => {
    console.log("User disconnected: " + socket.id);
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
