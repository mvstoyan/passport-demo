require('dotenv').config();
const express = require("express");
const app = express();
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require("bcrypt");
const MongoDBStore = require('connect-mongodb-session')(session)

// Connect to MongoDB database
const mongoDb = process.env.MONGO_URI;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

// Define user schema
const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
  })
);

// Create new MongoDB session store
var store = new MongoDBStore({
  uri: process.env.MONGO_URI,
  collection: 'sessions'
});

// Catch errors
store.on('error', function (error) {
  console.log(error);
});

// Configure app settings
app.set("views", __dirname);
app.set("view engine", "ejs");

// Configure app middleware
app.use(session({
  secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true,
  store: store
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

// Set up middleware to pass the current user to views
app.use(function(req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

// Define middleware to require authentication for certain routes
const authMiddleware = (req, res, next) => {
  if (!req.user) {
    if (!req.session.messages) {
      req.session.messages = [];
    }
    req.session.messages.push("You can't access that page before logon.");
    res.redirect('/');
  } else {
    next();
  }
}

// Define route handlers
app.get("/", (req, res) => {
  // Render index page with any messages in the session
  let messages = [];
  if (req.session.messages) {
    messages = req.session.messages;
    req.session.messages = [];
  }
  res.render("index", { messages });
});

app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.get("/log-out", (req, res) => {
  // Destroy session and redirect to home page
  req.session.destroy(function (err) {
    res.redirect("/");
  });
});

app.post("/sign-up", async (req, res, next) => {
  // Hash password and create new user in database
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await User.create({ username: req.body.username, password: hashedPassword });
    res.redirect("/");
  } catch (err) {
    return next(err);
  }
});

passport.use(
  // Configure passport to use local strategy for authentication
  new LocalStrategy(async (username, password, done) => {
    try {
      // Find user by username
      const user = await User.findOne({ username: username });
      if (!user) {
        // If no user found, return error
        return done(null, false, { message: "Incorrect username" });
      }
      // Compare password with hashed password in database
      bcrypt.compare(password, user.password, (err, result) => {
        if (result) {
          // If the passwords match, return the user object
          return done(null, user);
        } else {
          // If the passwords don't match, return false and an error message
          return done(null, false, { message: "Incorrect password" });
        }
      });
    } catch (err) {
      // If there's an error, return the error to the caller
      return done(err);
    }
  })
);

// Define how to serialize and deserialize user objects
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function(id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch(err) {
    done(err);
  }
});

// Handle requests to log in
app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
    failureMessage: true
  })
);

// Handle requests to restricted pages by requiring authentication
app.get('/restricted', authMiddleware, (req, res) => {
  if (!req.session.pageCount) {
    req.session.pageCount = 1;
  } else {
    req.session.pageCount++;
  }
  res.render('restricted', { pageCount: req.session.pageCount });
})

app.listen(3000, () => console.log("app listening on port 3000!"));
