require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const app = express();
const passport = require("passport");
const session = require("express-session");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

app.set("view engine", "ejs")
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: "This is our little secret.",
    resave: false,
    saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/usersDB")

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    displayNameGoogle: String,
    photos: Array,
    secret: [{type:String}],
    facebookId: String,
    displayNameFb:String,
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = new mongoose.model("User", userSchema);


passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, { id: user.id, username: user.username, name: user.name });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id, displayNameGoogle: profile.displayName, photos: profile.photos }, function (err, user) {
            return cb(err, user);
        });
    }
));
passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id, displayNameFb: profile.displayName }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("secrets")
    } else {
        res.render("home")
    }
});
app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.log(err);
        } else {
            res.redirect("/");
        }
    });
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/secrets", (req, res) => {
    if(req.isAuthenticated()){
  User.find({"secret.0" : {$ne:null}}).then(foundUser=>{
if(foundUser){
    res.render("secrets", {userWithSecrets:foundUser})
}
  }).catch(err=>{
    console.log(err);
  })
}else{
    res.redirect("/login")
}

});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect secrets.
        res.redirect('/secrets');
    });

    app.get('/auth/facebook',
    passport.authenticate('facebook'));
  
  app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect Secrets.
      res.redirect('/secrets');
    });

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit")
    } else {
        res.redirect("/register")
    }
});

app.post("/register", (req, res) => {
    User.register(new User({ username: req.body.username }), req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            return res.redirect("/register");
        }
        passport.authenticate("local")(req, res, () => {
            res.redirect("/secrets");
        });
    });
});

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, function (err) {
        if (err) {
            console.log(err),
                res.redirect("/login")
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets")
            });

        }
    });
});

app.post("/submit", (req, res)=>{
    const submittedSecret = req.body.secret;
    User.findById(req.user.id).then(foundUser=>{
if(foundUser){
    foundUser.secret.push(submittedSecret);
    foundUser.save().then(function(){
            res.redirect("/secrets")
    });
}
    }).catch(err=>{
        console.log(err);
    });
});

app.listen("3000", () => {
    console.log("Server is up and running on port 3000");
});
