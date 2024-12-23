const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const Datastore = require("nedb-promises");

const app = express();
app.use(express.json());

const users = Datastore.create("Users.db");
const userRefreshTokens = Datastore.create("UserRefreshTokens.db");
const userInvalidTokens = Datastore.create("UserInvalidTokens.db");

app.get("/", (req, res) => {
  res.send("Authentication using Nodejs");
});

app.post("/api/register", async (req, res) => {
  // add confirmPassword
  try {
    const { email, password, role } = req.body;

    if (!email || !password) {
      return res.status(422).json({ message: "Please enter all fields!" });
    }

    if (await users.findOne({ email })) {
      return res.status(409).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await users.insert({
      email,
      password: hashedPassword,
      role: role ?? "user",
    });

    return res.status(201).json({
      message: "User registered successfully",
      id: newUser._id,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(422)
        .json({ message: "Please fill in all fields (email and password)" });
    }

    const user = await users.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: "Email or password is invalid" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: "Email or password is invalid" });
    }

    const accessToken = jwt.sign(
      { userId: user._id },
      process.env.ACCESS_TOKEN_SECRET,
      { subject: "accessApi", expiresIn: process.env.ACCESS_TOKEN_EXPIRES }
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_SECRET,
      { subject: "refreshToken", expiresIn: process.env.REFRESH_TOKEN_EXPIRES }
    );

    await userRefreshTokens.insert({
      refreshToken,
      userId: user._id,
    });

    return res.status(200).json({
      id: user._id,
      email: user.email,
      accessToken,
      refreshToken,
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.post("/api/refresh-token", async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh token not found" });
    }

    const decodedRefreshToken = jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const userRefreshToken = await userRefreshTokens.findOne({
      refreshToken,
      userId: decodedRefreshToken.userId,
    });

    if (!userRefreshToken) {
      return res
        .status(401)
        .json({ message: "Refresh token invalid or expired" });
    }

    await userRefreshTokens.remove({ _id: userRefreshToken._id });
    await userRefreshTokens.compactDatafile();

    const accessToken = jwt.sign(
      { userId: decodedRefreshToken.userId },
      process.env.ACCESS_TOKEN_SECRET,
      { subject: "accessApi", expiresIn: process.env.ACCESS_TOKEN_EXPIRES }
    );

    const newRefreshToken = jwt.sign(
      { userId: decodedRefreshToken.userId },
      process.env.REFRESH_TOKEN_SECRET,
      { subject: "refreshToken", expiresIn: process.env.REFRESH_TOKEN_EXPIRES }
    );

    await userRefreshTokens.insert({
      refreshToken: newRefreshToken,
      userId: decodedRefreshToken.userId,
    });

    return res.status(200).json({
      accessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    if (
      error instanceof jwt.TokenExpiredError ||
      error instanceof jwt.JsonWebTokenError
    ) {
      return res
        .status(401)
        .json({ message: "Refresh token invalid or expired" });
    }

    return res.status(500).json({ message: error.message });
  }
});

app.get("/api/logout", ensureAuthenticated, async (req, res) => {
  try {
    await userRefreshTokens.removeMany({ userId: req.user.id });
    await userRefreshTokens.compactDatafile();

    await userInvalidTokens.insert({
      accessToken: req.accessToken.value,
      userId: req.user.id,
      expirationTime: req.accessToken.exp,
    });

    return res.status(204).send();
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.get("/api/users", ensureAuthenticated, async (req, res) => {
  try {
    const user = await users.findOne({ _id: req.user.id });

    return res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.get(
  "/api/admin",
  ensureAuthenticated,
  authorize("admin"),
  async (req, res) => {
    return res.status(200).json({ message: "Welcome to admin page" });
  }
);

async function ensureAuthenticated(req, res, next) {
  const accessToken = req.headers.authorization;

  if (!accessToken) {
    return res.status(401).json({ message: "Access token not found" });
  }

  if (await userInvalidTokens.findOne({ accessToken })) {
    return res
      .status(401)
      .json({ message: "Access token invalid", code: "AccessTokenInvalid" });
  }

  try {
    const decodedAccessToken = jwt.verify(
      accessToken,
      process.env.ACCESS_TOKEN_SECRET
    );

    req.accessToken = { value: accessToken, exp: decodedAccessToken.exp };
    req.user = { id: decodedAccessToken.userId };

    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return res
        .status(401)
        .json({ message: "Access token expired", code: "AccessTokenExpired" });
    } else if (error instanceof jwt.JsonWebTokenError) {
      return res
        .status(401)
        .json({ message: "Access token invalid", code: "AccessTokenInvalid" });
    } else {
      return res.status(500).json({ message: error.message });
    }
  }
}

function authorize(roles) {
  return async function (req, res, next) {
    const user = await users.findOne({ _id: req.user.id });

    if (!user || !roles.includes(user.role)) {
      res.status(403).json({ message: "Access denied" });
    }

    next();
  };
}

app.listen(3000, () => console.log("Server started on port 3000"));
