const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
const multer = require("multer");
const path = require("path");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// MySQL connection string (update credentials as needed)
const db = mysql.createConnection(
  "mysql://JMJ_structure:6715ca0067dfaaee9ec452ce17b0f2065aed8d5f@xlfqu.h.filess.io:3307/JMJ_structure"
);

db.connect((err) => {
  if (err) {
    console.error("MySQL connection error:", err);
    process.exit(1);
  }
  console.log("Connected to MySQL");
});

const SESSION_SECRET = "chatapp";

// Use MySQL session store for production
const sessionStore = new MySQLStore({}, db.promise());

// ====================================================
// Protect Static Files Middleware
// ====================================================
const publicWhitelist = ["/", "/index.html", "/login.html", "/forgot-password.html"];
app.use((req, res, next) => {
  if (publicWhitelist.includes(req.path)) return next();
  if (req.session && req.session.user) return next();
  return res.redirect("/");
});

// ====================================================
// Standard Middleware Setup
// ====================================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("trust proxy", 1);

// Session setup
app.use(
  session({
    key: "chatapp_session",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
      secure: true, // Set to true if using HTTPS
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

// Serve static files from public folder
app.use(express.static("public"));

// ====================================================
// File Upload Setup (Multer)
// ====================================================
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

app.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file)
    return res.status(400).json({ message: "No file uploaded." });
  const fileUrl = `/uploads/${req.file.filename}`;
  let mediaType = "";
  if (req.file.mimetype.startsWith("image/")) mediaType = "image";
  else if (req.file.mimetype.startsWith("video/")) mediaType = "video";
  else mediaType = "file";
  return res.status(200).json({
    message: "File uploaded successfully!",
    fileUrl,
    mediaType,
  });
});

// ====================================================
// Authentication Endpoints
// ====================================================
app.post("/register", (req, res) => {
  const { username, password, full_name, email } = req.body;
  if (!username || !password || !full_name || !email)
    return res.status(400).json({ message: "All fields are required." });
  const checkQuery = "SELECT * FROM users WHERE email = ?";
  db.query(checkQuery, [email], (err, results) => {
    if (err) return res.status(500).json({ message: "Database error." });
    if (results.length > 0)
      return res.status(409).json({ message: "Email already registered." });
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) return res.status(500).json({ message: "Error processing password." });
      const query = "INSERT INTO users (username, password, full_name, email) VALUES (?, ?, ?, ?)";
      db.query(query, [username, hashedPassword, full_name, email], (err, result) => {
        if (err) return res.status(500).json({ message: "Error registering user." });
        return res.status(200).json({ message: "Registration successful!" });
      });
    });
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Email and password are required." });
  const query = "SELECT * FROM users WHERE email = ?";
  db.query(query, [email], (err, results) => {
    if (err) return res.status(500).json({ message: "Database error." });
    if (results.length === 0) return res.status(401).json({ message: "User not found." });
    const user = results[0];
    bcrypt.compare(password, user.password, (err, match) => {
      if (err || !match)
        return res.status(401).json({ message: "Incorrect password." });
      req.session.user = { username: user.username, full_name: user.full_name, email: user.email };
      console.log("User logged in:", req.session.user);
      return res.status(200).json({ message: "Login successful!", user: req.session.user });
    });
  });
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ message: "Logout error." });
    res.clearCookie("chatapp_session");
    return res.status(200).json({ message: "Logged out successfully!" });
  });
});

app.get("/me", (req, res) => {
  if (req.session.user)
    return res.status(200).json({ loggedIn: true, user: req.session.user });
  return res.status(200).json({ loggedIn: false });
});

// ====================================================
// Profile Endpoints
// ====================================================
app.get("/profile", (req, res) => {
  if (!req.session.user)
    return res.status(401).json({ message: "User not logged in." });
  const username = req.session.user.username;
  const query = "SELECT username, full_name, email, profile_picture FROM users WHERE username = ?";
  db.query(query, [username], (err, results) => {
    if (err) return res.status(500).json({ message: "Database error." });
    if (results.length === 0)
      return res.status(404).json({ message: "User not found." });
    return res.status(200).json({ userProfile: results[0] });
  });
});

app.put("/profile", (req, res) => {
  if (!req.session.user)
    return res.status(401).json({ message: "User not logged in." });
  const username = req.session.user.username;
  const { full_name, email, profile_picture } = req.body;
  if (!full_name || !email)
    return res.status(400).json({ message: "Full name and email are required." });
  const updateQuery = "UPDATE users SET full_name = ?, email = ?, profile_picture = ? WHERE username = ?";
  db.query(updateQuery, [full_name, email, profile_picture || null, username], (err, result) => {
    if (err) return res.status(500).json({ message: "Error updating profile." });
    req.session.user.full_name = full_name;
    req.session.user.email = email;
    return res.status(200).json({ message: "Profile updated successfully!" });
  });
});

// ====================================================
// Room Endpoints
// ====================================================
app.get("/rooms", (req, res) => {
  const query = "SELECT room_name FROM rooms";
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ message: "Error fetching rooms." });
    const rooms = results.map((row) => row.room_name);
    res.status(200).json({ rooms });
  });
});

app.post("/rooms", (req, res) => {
  console.log("Session data:", req.session);
  const { room_name, room_code } = req.body;
  if (!room_name)
    return res.status(400).json({ message: "Room name is required." });
  const created_by = req.session?.user?.username;
  if (!created_by)
    return res.status(401).json({ message: "You must be logged in to create a room." });
  console.log("Creating room by user:", created_by);
  const checkUserQuery = "SELECT * FROM users WHERE username = ?";
  db.query(checkUserQuery, [created_by], (err, userResults) => {
    if (err) return res.status(500).json({ message: "Database error." });
    if (userResults.length === 0)
      return res.status(400).json({ message: "User does not exist. Please log in." });
    const insertRoomQuery = "INSERT INTO rooms (room_name, created_by, room_code) VALUES (?, ?, ?)";
    db.query(insertRoomQuery, [room_name, created_by, room_code || null], (err, result) => {
      if (err) return res.status(500).json({ message: "Error creating room." });
      res.status(200).json({ message: "Room created successfully!", room_name });
    });
  });
});

app.get("/roomAdmin", (req, res) => {
  const room = req.query.room;
  if (!room) return res.status(400).json({ message: "Room parameter is required." });
  const query = "SELECT created_by FROM rooms WHERE room_name = ?";
  db.query(query, [room], (err, results) => {
    if (err) return res.status(500).json({ message: "Database error." });
    if (results.length === 0)
      return res.status(404).json({ message: "Room not found." });
    return res.status(200).json({ created_by: results[0].created_by });
  });
});

// ====================================================
// Search Users Endpoint
// ====================================================
app.get("/search-users", (req, res) => {
  if (!req.session.user)
    return res.status(401).json({ message: "User not logged in." });
  const currentUser = req.session.user.username;
  const queryParam = req.query.query;
  if (!queryParam)
    return res.status(400).json({ message: "Query parameter is required." });
  const searchQuery = `
    SELECT username, full_name, email, profile_picture 
    FROM users 
    WHERE (username LIKE ? OR full_name LIKE ? OR email LIKE ?)
      AND username != ?
  `;
  const likeQuery = `%${queryParam}%`;
  db.query(searchQuery, [likeQuery, likeQuery, likeQuery, currentUser], (err, results) => {
    if (err) return res.status(500).json({ message: "Database error." });
    return res.status(200).json({ users: results });
  });
});

// ====================================================
// NodeMailer & Password Reset
// ====================================================
const transporter = nodemailer.createTransport({
  host: "smtp.office365.com",
  port: 587,
  secure: false,
  auth: {
    user: "jerry_2044@outlook.com",
    pass: "ilovemymom12345"
  },
  tls: {
    ciphers: "SSLv3"
  }
});

app.post("/reset-password-request", (req, res) => {
  const { email } = req.body;
  if (!email)
    return res.status(400).json({ message: "Email is required." });
  const query = "SELECT * FROM users WHERE email = ?";
  db.query(query, [email], (err, results) => {
    if (err) return res.status(500).json({ message: "Database error." });
    if (results.length === 0)
      return res.status(404).json({ message: "User not found." });
    const user = results[0];
    const token = crypto.randomBytes(20).toString("hex");
    const expires = new Date(Date.now() + 3600000);
    const updateQuery = "UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE email = ?";
    db.query(updateQuery, [token, expires, email], (err, result) => {
      if (err) return res.status(500).json({ message: "Database error." });
      const resetLink = `https://chat-app-project-lj99.onrender.com/reset-password?token=${token}`;
      const mailOptions = {
        from: '"ChatApp Support" <jerry_2044@outlook.com>',
        to: user.email || email,
        subject: 'Password Reset Request',
        text: `You have requested a password reset. Please click on the following link to reset your password: ${resetLink}. This link is valid for 1 hour.`,
        html: `<p>You have requested a password reset.</p>
               <p>Please click on the link below to reset your password:</p>
               <p><a href="${resetLink}">${resetLink}</a></p>
               <p>This link is valid for 1 hour.</p>`
      };
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) return res.status(500).json({ message: "Error sending email." });
        console.log("Password reset email sent:", info.response);
        return res.status(200).json({ message: "Password reset email has been sent." });
      });
    });
  });
});

// ====================================================
// Socket.IO Handling
// ====================================================
io.on("connection", (socket) => {
  console.log("A user connected: " + socket.id);

  // Register user for private messaging (join personal room).
  socket.on("register user", (data) => {
    if (data.username) {
      socket.join(data.username);
      console.log(`Socket ${socket.id} joined personal room: ${data.username}`);
    }
  });

  // Join room event for public chat rooms only.
  socket.on("join room", (data) => {
    const roomName = data.roomName;
    const providedCode = data.code || "";
    // No special DM branch is present now.
    const roomQuery = "SELECT room_code FROM rooms WHERE room_name = ?";
    db.query(roomQuery, [roomName], (err, results) => {
      if (err) {
        console.error(err);
        socket.emit("join error", "Database error.");
        return;
      }
      if (results.length === 0) {
        socket.emit("join error", "Room not found.");
        return;
      }
      const roomCode = results[0].room_code;
      if (roomCode && roomCode !== providedCode) {
        socket.emit("join error", "Incorrect room code.");
        return;
      }
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
  });

  // Listen for typing events.
  socket.on("typing", (data) => {
    const { room, username } = data;
    socket.to(room).emit("typing", { username });
  });

  // Listen for stop typing events.
  socket.on("stop typing", (data) => {
    const { room, username } = data;
    socket.to(room).emit("stop typing", { username });
  });

  // Handle incoming chat messages (for public chat rooms).
  socket.on("chat message", (data) => {
    const { username, message, room, media, mediaType } = data;
    if (!username || (!message && !media) || !room) return;
    if (media) {
      const query = "INSERT INTO messages (room, username, message, media, mediaType) VALUES (?, ?, ?, ?, ?)";
      db.query(query, [room, username, message || "", media, mediaType], (err, result) => {
        if (err) {
          console.error("Error saving media message:", err);
          return;
        }
        io.to(room).emit("chat message", { username, message, media, mediaType, id: result.insertId, room });
      });
    } else {
      const query = "INSERT INTO messages (room, username, message) VALUES (?, ?, ?)";
      db.query(query, [room, username, message], (err, result) => {
        if (err) {
          console.error("Error saving message:", err);
          return;
        }
        io.to(room).emit("chat message", { username, message, id: result.insertId, room });
      });
    }
  });

  // Handle deletion of a single message by room admin.
  socket.on("delete message", (data) => {
    const { room, messageId, username } = data;
    if (!room || !messageId || !username) return;
    const query = "SELECT created_by FROM rooms WHERE room_name = ?";
    db.query(query, [room], (err, results) => {
      if (err) {
        console.error(err);
        return;
      }
      if (results.length === 0) return;
      if (results[0].created_by !== username) {
        socket.emit("admin error", "Only the room administrator can delete messages.");
        return;
      }
      const deleteQuery = "DELETE FROM messages WHERE id = ?";
      db.query(deleteQuery, [messageId], (err, result) => {
        if (err) {
          console.error("Error deleting message:", err);
          return;
        }
        io.to(room).emit("message deleted", { messageId });
      });
    });
  });

  // Handle room deletion by room admin.
  socket.on("delete room", (data) => {
    const { room, username } = data;
    if (!room || !username) return;
    const query = "SELECT created_by FROM rooms WHERE room_name = ?";
    db.query(query, [room], (err, results) => {
      if (err) {
        console.error(err);
        return;
      }
      if (results.length === 0) return;
      if (results[0].created_by !== username) {
        socket.emit("admin error", "Only the room creator can delete this room.");
        return;
      }
      db.query("DELETE FROM messages WHERE room = ?", [room], (err, result) => {
        if (err) {
          console.error("Error deleting messages in room:", err);
        }
        db.query("DELETE FROM rooms WHERE room_name = ?", [room], (err, result) => {
          if (err) {
            console.error("Error deleting room:", err);
            return;
          }
          io.to(room).emit("room deleted", { room });
        });
      });
    });
  });

  socket.on("disconnect", () => {
    console.log("User disconnected: " + socket.id);
  });
});

// ====================================================
// Start the Server
// ====================================================
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
