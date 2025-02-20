const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
const multer = require("multer");
const path = require("path");
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// MySQL connection
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

// Optional: Use MySQL session store for production
const sessionStore = new MySQLStore({}, db.promise());

// Middleware for parsing bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("trust proxy", 1); // Required for sessions to work on some platforms

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
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    },
  })
);

// Serve static files from public folder
app.use(express.static("public"));

//////////////////////////////
// FILE UPLOAD SETUP (Multer)
//////////////////////////////
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
  if (!req.file)
    return res.status(400).json({ message: "No file uploaded." });
  const fileUrl = `/uploads/${req.file.filename}`;
  let mediaType = "";
  if (req.file.mimetype.startsWith("image/")) mediaType = "image";
  else if (req.file.mimetype.startsWith("video/")) mediaType = "video";
  else mediaType = "file";
  return res
    .status(200)
    .json({
      message: "File uploaded successfully!",
      fileUrl,
      mediaType,
    });
});

//////////////////////////////
// AUTHENTICATION ENDPOINTS
//////////////////////////////

// Registration endpoint
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res
      .status(400)
      .json({ message: "Username and password are required." });
  const checkQuery = "SELECT * FROM users WHERE username = ?";
  db.query(checkQuery, [username], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Database error." });
    }
    if (results.length > 0)
      return res.status(409).json({ message: "Username already exists." });
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.error(err);
        return res
          .status(500)
          .json({ message: "Error processing password." });
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
    return res
      .status(400)
      .json({ message: "Username and password are required." });
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
      console.log("User logged in:", req.session.user);
      return res
        .status(200)
        .json({ message: "Login successful!", username: user.username });
    });
  });
});

// Logout endpoint
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).json({ message: "Logout error." });
    }
    res.clearCookie("chatapp_session");
    return res.status(200).json({ message: "Logged out successfully!" });
  });
});

// Session check endpoint
app.get("/me", (req, res) => {
  if (req.session.user)
    return res.status(200).json({ loggedIn: true, user: req.session.user });
  return res.status(200).json({ loggedIn: false });
});

//////////////////////////////
// ROOM ENDPOINTS
//////////////////////////////

// List available rooms
app.get("/rooms", (req, res) => {
  const query = "SELECT room_name FROM rooms";
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Error fetching rooms." });
    }
    const rooms = results.map((row) => row.room_name);
    res.status(200).json({ rooms });
  });
});

// Create a new room with an optional room code
app.post("/rooms", (req, res) => {
  console.log("Session data:", req.session);
  const { room_name, room_code } = req.body; // Accept room_code from client
  if (!room_name)
    return res.status(400).json({ message: "Room name is required." });
  const created_by = req.session?.user?.username;
  if (!created_by)
    return res
      .status(401)
      .json({ message: "You must be logged in to create a room." });
  console.log("Creating room by user:", created_by);
  // Check if the user exists in the database
  const checkUserQuery = "SELECT * FROM users WHERE username = ?";
  db.query(checkUserQuery, [created_by], (err, userResults) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error." });
    }
    if (userResults.length === 0) {
      console.error(`User ${created_by} does not exist in users table.`);
      return res
        .status(400)
        .json({ message: "User does not exist. Please log in." });
    }
    // Insert the room into the database, storing the room code if provided
    const insertRoomQuery =
      "INSERT INTO rooms (room_name, created_by, room_code) VALUES (?, ?, ?)";
    db.query(
      insertRoomQuery,
      [room_name, created_by, room_code || null],
      (err, result) => {
        if (err) {
          console.error("Error creating room:", err);
          return res.status(500).json({ message: "Error creating room." });
        }
        res
          .status(200)
          .json({ message: "Room created successfully!", room_name });
      }
    );
  });
});

// Endpoint to fetch room admin
app.get("/roomAdmin", (req, res) => {
  const room = req.query.room;
  if (!room)
    return res
      .status(400)
      .json({ message: "Room parameter is required." });
  const query = "SELECT created_by FROM rooms WHERE room_name = ?";
  db.query(query, [room], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Database error." });
    }
    if (results.length === 0)
      return res.status(404).json({ message: "Room not found." });
    return res.status(200).json({ created_by: results[0].created_by });
  });
});




// Configure the transporter (update with your SMTP details)
const transporter = nodemailer.createTransport({
  host: "smtp.office365.com",
  port: 587,
  secure: false, // use TLS
  auth: {
    user: "jerry_2044@outlook.com", // your Outlook email address
    pass: "ilovemymom12345"             // your Outlook email password or app-specific password
  },
  tls: {
    ciphers: "SSLv3"
  }
});
// Password reset request endpoint
app.post("/reset-password-request", (req, res) => {
  const { username } = req.body; // assume username holds the user's email address
  if (!username)
    return res.status(400).json({ message: "Username (email) is required." });

  // Check if the user exists.
  const query = "SELECT * FROM users WHERE username = ?";
  db.query(query, [username], (err, results) => {
    if (err) {
      console.error("DB error:", err);
      return res.status(500).json({ message: "Database error." });
    }
    if (results.length === 0)
      return res.status(404).json({ message: "User not found." });

    const user = results[0];
    // Generate a token and set expiry (1 hour from now)
    const token = crypto.randomBytes(20).toString("hex");
    const expires = new Date(Date.now() + 3600000); // 1 hour from now

    // Update the user record with the token and expiry.
    const updateQuery = "UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE username = ?";
    db.query(updateQuery, [token, expires, username], (err, result) => {
      if (err) {
        console.error("DB error:", err);
        return res.status(500).json({ message: "Database error." });
      }
      
      // Construct the reset link (update with your domain)
      const resetLink = `https://chat-app-project-lj99.onrender.com/reset-password?token=${token}`;
      
      // Prepare the email options
      const mailOptions = {
        from: '"ChatApp Support" <jerry_2044@outlook.com>',
        to: user.email || username, // if you store email in a dedicated field use user.email; otherwise, username
        subject: 'Password Reset Request',
        text: `You have requested a password reset. Please click on the following link to reset your password: ${resetLink}. This link is valid for 1 hour.`,
        html: `<p>You have requested a password reset.</p>
               <p>Please click on the link below to reset your password:</p>
               <p><a href="${resetLink}">${resetLink}</a></p>
               <p>This link is valid for 1 hour.</p>`
      };

      // Send the email
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending email:', error);
          return res.status(500).json({ message: "Error sending email." });
        }
        console.log('Password reset email sent:', info.response);
        return res.status(200).json({ message: "Password reset email has been sent." });
      });
    });
  });
});


//////////////////////////////
// SOCKET.IO HANDLING
//////////////////////////////

io.on("connection", (socket) => {
  console.log("A user connected: " + socket.id);

  // Handle room joining with an optional room code
  socket.on("join room", (data) => {
    const roomName = data.roomName;
    const providedCode = data.code || "";
    // Get the room's room_code from the database
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
      // If a room code exists and does not match the provided code, reject the join
      if (roomCode && roomCode !== providedCode) {
        socket.emit("join error", "Incorrect room code.");
        return;
      }
      // Allow the user to join the room
      socket.join(roomName);
      console.log(`Socket ${socket.id} joined room: ${roomName}`);
      socket.emit("joined room", roomName);
      // Fetch chat history for the room
      const query =
        "SELECT * FROM messages WHERE room = ? ORDER BY timestamp ASC";
      db.query(query, [roomName], (err, results) => {
        if (err) {
          console.error("Error fetching chat history for room:", err);
          return;
        }
        socket.emit("chat history", results);
      });
    });
  });

  // Handle incoming chat messages (with optional media)
  socket.on("chat message", (data) => {
    const { username, message, room, media, mediaType } = data;
    if (!username || (!message && !media) || !room) return;
    if (media) {
      const query =
        "INSERT INTO messages (room, username, message, media, mediaType) VALUES (?, ?, ?, ?, ?)";
      db.query(
        query,
        [room, username, message || "", media, mediaType],
        (err, result) => {
          if (err) {
            console.error("Error saving media message:", err);
            return;
          }
          io.to(room).emit("chat message", {
            username,
            message,
            media,
            mediaType,
            id: result.insertId,
          });
        }
      );
    } else {
      const query =
        "INSERT INTO messages (room, username, message) VALUES (?, ?, ?)";
      db.query(query, [room, username, message], (err, result) => {
        if (err) {
          console.error("Error saving message:", err);
          return;
        }
        io.to(room).emit("chat message", {
          username,
          message,
          id: result.insertId,
        });
      });
    }
  });

  // Handle deletion of a single message by room admin
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
        socket.emit(
          "admin error",
          "Only the room administrator can delete messages."
        );
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

  // Handle room deletion by room admin
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
        socket.emit(
          "admin error",
          "Only the room creator can delete this room."
        );
        return;
      }
      // Optionally, delete all messages in the room first.
      db.query("DELETE FROM messages WHERE room = ?", [room], (err, result) => {
        if (err) {
          console.error("Error deleting messages in room:", err);
        }
        // Now delete the room itself.
        db.query(
          "DELETE FROM rooms WHERE room_name = ?",
          [room],
          (err, result) => {
            if (err) {
              console.error("Error deleting room:", err);
              return;
            }
            io.to(room).emit("room deleted", { room });
          }
        );
      });
    });
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
