const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();

// Enable CORS
app.use(cors({
  origin: '*',
  credentials: true
}));
app.use(express.json());

// File-based storage (Vercel uses /tmp for writable storage)
const DATA_FILE = path.join('/tmp', 'users.json');

// Initialize users file
if (!fs.existsSync(DATA_FILE)) {
  fs.writeFileSync(DATA_FILE, JSON.stringify([]));
}

// Helper functions
const getUsers = () => {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return [];
  }
};

const saveUsers = (users) => {
  fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
};

const findUserByEmail = (email) => {
  const users = getUsers();
  return users.find(u => u.email === email);
};

const addUser = (user) => {
  const users = getUsers();
  users.push(user);
  saveUsers(users);
  return user;
};

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Register Endpoint
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, mobile, fullName, profileName, dateOfBirth } = req.body;

    const existingUser = findUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = {
      id: Date.now().toString(),
      email,
      password: hashedPassword,
      mobile,
      fullName,
      profileName,
      dateOfBirth,
      createdAt: new Date().toISOString(),
    };

    addUser(user);

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user.id,
        email: user.email,
        profileName: user.profileName,
      },
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Login Endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = findUserByEmail(email);
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        profileName: user.profileName,
      },
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Verify Token Endpoint
app.get('/api/auth/verify', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const users = getUsers();
    const user = users.find(u => u.id === decoded.userId);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const { password, ...userWithoutPassword } = user;
    res.json({ user: userWithoutPassword });
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
});

// Update Profile Endpoint
app.put('/api/auth/profile', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const users = getUsers();
    const userIndex = users.findIndex(u => u.id === decoded.userId);
    
    if (userIndex === -1) {
      return res.status(404).json({ message: 'User not found' });
    }

    const { fullName, profileName, mobile, dateOfBirth, bio, location, favoriteGenre } = req.body;

    users[userIndex] = {
      ...users[userIndex],
      fullName: fullName || users[userIndex].fullName,
      profileName: profileName || users[userIndex].profileName,
      mobile: mobile || users[userIndex].mobile,
      dateOfBirth: dateOfBirth || users[userIndex].dateOfBirth,
      bio: bio !== undefined ? bio : users[userIndex].bio,
      location: location !== undefined ? location : users[userIndex].location,
      favoriteGenre: favoriteGenre !== undefined ? favoriteGenre : users[userIndex].favoriteGenre,
    };

    saveUsers(users);

    const { password, ...userWithoutPassword } = users[userIndex];
    res.json({ message: 'Profile updated successfully', user: userWithoutPassword });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

module.exports = app;
