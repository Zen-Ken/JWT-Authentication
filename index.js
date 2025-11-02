import 'dotenv/config';
import express from 'express';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';

const users = [
  { 
    id: 1,
    username: "jdoe",
    password: "password123"
  },
];

const revokedRefreshTokens = new Set();
    
const app = express();
app.use(express.json());
app.use(cookieParser());

app.get("/", authenticateToken, (req, res) => {
  const username = users.filter(users => users.username === req.user.name);
  
  res.json(`Welcome back, ${username[0].username}!`);
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401); // unauthorized

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (!username) {
    return res.status(400).json({ error: "Username required" });
  }

  if (!password) {
    return res.status(400).json({ error: "Password required" });
  }

  const foundUser = users.find(
    (user) => user.username === username && user.password === req.body.password
  );

  if (!foundUser) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const user = { name: foundUser.username };

  const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: 10});
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
  
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: true,
  });
  
  res.json({ accessToken: accessToken }); // Only access token in JSON
});

app.post('/token', (req, res) => {
  const refreshToken = req.cookies.refreshToken; // From cookie
  
  if (!refreshToken) return res.sendStatus(401);
  
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    
    const newAccessToken = jwt.sign({username: user.username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: 180 });
    const newRefreshToken = jwt.sign({username: user.username }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

    // Set new refresh token in HttpOnly cookie
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: true,    // HTTPS only
    });
    
    // Only send access token in JSON
    res.json({ accessToken: newAccessToken });
  });
});

// Introspect endpoint to validate token and return user info as per OAuth2 Token Introspection 
// Verify token with JWT other option is opaque
app.post("/introspect", (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (token == null) return res.sendStatus(401); // unauthorized

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403)
    
    return res.status(200).json(user);
  });
})

app.post("/logout", (req, res) => {
  const authHeader  = req.headers['authorization'];
  const token = authHeader  && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401); // unauthorized

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    
    // store revoke old refresh token so user doesn't stay logged in
    // can clean up when expires
    const refreshToken = req.cookies.refreshToken;
    revokedRefreshTokens.add(refreshToken);

    // if need more security, store revoked access tokens
    // but access tokens are short lived so not always necessary
    
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: true,
    });

    res.json("Logged out"); // No content
  });
});

app.post("/register", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    return res.status(409).json({ error: "User already exists" });
  }

  const user = {
    id: users.length + 1,
    username,
    password
  };

  users.push(user);

  res.status(201).json({ message: "User created", userId: user.id });
});

app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});