require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const { body, validationResult } = require("express-validator");
const morgan = require("morgan");
const bodyParser = require("body-parser");
const cors = require("cors");
const axios = require("axios");
const User = require("./models/User");

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(cors());
app.use(morgan("combined"));

// Database connection
mongoose
  .connect("mongodb://localhost:27017/formapp", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log(err));
// password validation regex

const passwordRegex =
  /^(?=.*[A-Z])(?=.*\d.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]{8,}$/;
// Routes
app.post(
  "/api/register",
  [
    body("username").notEmpty().withMessage("Username is required"),
    body("email").isEmail().withMessage("Email is invalid"),
    body("password")
      .isLength({ min: 6 })
      .matches(passwordRegex)
      .withMessage(
        "Password must contain at least one uppercase letter, two numeric digits, one special character, and be at least 8 characters long"
      ),
    body("confirmPassword").custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Passwords do not match");
      }
      return true;
    }),
    body("captcha").notEmpty().withMessage("Captcha is required"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password, captcha } = req.body;

    // Verify reCAPTCHA token
    const secretKey = process.env.RECAPTCHA_SECRET_KEY;
    const response = await axios.post(
      `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captcha}`
    );
    const { success } = response.data;

    if (!success) {
      return res
        .status(400)
        .json({ errors: [{ msg: "Captcha validation failed" }] });
    }

    try {
      // Check if user exists
      let user = await User.findOne({ email });
      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: "User already exists" }] });
      }

      // Encrypt password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Create new user
      user = new User({
        username,
        email,
        password: hashedPassword,
      });

      await user.save();

      res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server error");
    }
  }
);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Something broke!");
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
