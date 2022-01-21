const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const User = require("./userModel");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const auth = require("./middleware/auth");

require("dotenv").config();

const app = express();

app.use(cookieParser());
app.use(express.static("./static"));
app.use(express.json());
app.use(
  express.urlencoded({
    extended: false,
  })
);

app.listen(5000, () => console.log("Server started"));

mongoose.connect(process.env.MONGODB_CONNECT, (err) => {
  if (err) return console.log(err);
  console.log("Connected to the db");
});

app.post("/register", async (req, res) => {
  const { email, password, passwordRepeat } = req.body;

  if (!email || !password || !passwordRepeat) {
    return res.status(400).json({
      errorMessage: "Please enter all required fields.",
    });
  }

  if (password !== passwordRepeat) {
    return res.status(400).json({
      errorMessage: "The passwords must match.",
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      errorMessage: "The password must be at least 6 characters.",
    });
  }

  const passwordHash = bcrypt.hashSync(password);

  await User.create({
    email,
    passwordHash,
  });

  res.end();
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(401).json({
      errorMessage: "Please enter all required data.",
    });

  const userInDB = await User.findOne({ email });

  if (!userInDB)
    return res.status(401).json({
      errorMessage: "Login failed.",
    });

  const passwordCorrect = bcrypt.compareSync(password, userInDB.passwordHash);

  if (!passwordCorrect)
    return res.status(401).json({
      errorMessage: "Login failed.",
    });

  const token = jwt.sign(
    {
      id: userInDB._id,
    },
    process.env.JWT_SECRET
  );

  res
    .cookie("auth-token", token, {
      httpOnly: true,
    })
    .end();
});

app.get("/dosomething", auth, (req, res) => {
  res.send(req.user.email);
});
