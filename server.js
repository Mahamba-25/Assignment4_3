const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const path = require('path');
const multer = require('multer');
require('dotenv').config();

// Import the User model
const User = require('./models/User');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB Atlas
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('Connection error:', err));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
}));

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'public/uploads/'),
    filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});
const upload = multer({ storage });

// Routes
app.get('/', (req, res) => res.render('index'));
app.get('/register', (req, res) => res.render('register', { error: null }));
app.get('/login', (req, res) => res.render('login', { error: null }));
app.get('/dashboard', requireAuth, (req, res) => {
    res.render('dashboard', { user: req.session.user });
});
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Registration
app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Debug: Log the form data
        console.log('Form data:', { username, email, password });

        // Check if the email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.render('register', { error: 'Email already exists. Please use a different email.' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const user = new User({ username, email, password: hashedPassword });
        await user.save();

        // Redirect to login page
        res.redirect('/login');
    } catch (err) {
        console.error('Registration error:', err);
        res.render('register', { error: 'Registration failed. Please try again.' });
    }
});

// Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.user = user;
        res.redirect('/dashboard');
    } else {
        res.render('login', { error: 'Invalid credentials' });
    }
});

// Profile Picture Upload
app.post('/upload', upload.single('profilePic'), (req, res) => {
    if (!req.file) return res.render('error', { message: 'No file uploaded' });
    req.session.user.profilePic = req.file.filename;
    res.redirect('/dashboard');
});

// Middleware to check if user is authenticated
function requireAuth(req, res, next) {
    if (!req.session.user) return res.redirect('/login');
    next();
}

// Start server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));