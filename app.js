require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const app = express();

//connect bodyParser, Public folder and Ejs to Express
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.set("view engine", "ejs");

//Settings up the sessions package to use express
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false,
  // cookie: { secure: true }
}));

//setting up passport to use express
app.use(passport.initialize());
app.use(passport.session());

//mongoose connection
mongoose.set("strictQuery", false);
mongoose.connect(process.env.MONGO_URI, {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  secret: String,
  googleId: String
});

//Add passportlocalMongoose plugin to UserSchema
userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, {id: user.id, username: user.name, name: user.name});
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy(
  {
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOne({googleId: profile.id}).then((user) => {
      if (user) {
        return done(null, user);
      } else {
        const newUser = new User ({ googleId: profile.id });
        newUser.save().then((user) => {
          return done(null, user);
        }).catch((err) => { console.log(err); });
      }
    }).catch((err) => { console.log(err); });
  }
));



app.get("/", function (req, res) {
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }), 
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  User.find({"secret": {$ne: null}}).then((foundUsers) => {
    if (foundUsers) {
      res.render("secrets", {usersWithSecrets: foundUsers});
    }
  }).catch((err) => { console.log(err); });
});

app.get("/submit", function (req, res) {
  res.render("submit");
});

app.get("/logout", function (req, res) {
  req.logout();
  res.redirect("/");
});



// post requests
app.post("/register", function (req, res) {
  User.register({username: req.body.username}, req.body.password).then(() => {
    passport.authenticate("local")(req, res, () => {
      res.redirect("/secrets");
    });
  }).catch((err) => { 
    console.log(err);
    res.redirect("/register");
  });
});

app.post("/login", function (req, res) {
  const user = new User ({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function (err) {
    if (!err) {
      passport.authenticate("local")(req, res, () => {
        res.redirect("secrets");
      });
    } else {
      console.log(err);
    }
  });
});

app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret;

  User.findById(req.user._id).then((foundUser) => {
    if (foundUser) {
      foundUser.secret = submittedSecret;
      foundUser.save().then(() => {
        res.redirect("/secrets");
      });
    }
  }).catch((err) => { console.log(err); });
});




app.listen(process.env.port || 3000, () => {
  console.log("Server has started on port 3000");
});


// Level 1 Encryption is basically storing a username and password in the database
// Calling .find on it and allowing user login to their accounts with correct details
