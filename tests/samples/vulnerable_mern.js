/**
 * vulnerable_mern.js
 * Intentionally vulnerable MERN-stack server for scanner testing.
 * DO NOT deploy this file — it exists solely as a scan target.
 */

const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const _ = require('lodash');
const yaml = require('js-yaml');

const app = express();
app.use(express.json());

// --- MERN-CONF-003: Express app created without helmet() ---

// --- MERN-SEC-002: MongoDB URI with embedded credentials ---
mongoose.connect('mongodb://admin:SuperSecret123@localhost:27017/myapp');

// --- MERN-SEC-001: Hardcoded JWT secret ---
const jwtSecret = 'mysecret';

// -------------------------------------------------------
// Auth routes
// -------------------------------------------------------
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // --- MERN-NOSQL-001: req.body passed directly to Mongoose query ---
    const user = await User.findOne(req.body);

    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    // --- MERN-JWT-001: JWT signed with hardcoded weak secret ---
    const token = jwt.sign({ id: user._id, role: user.role }, 'mysecret');

    res.json({ token });
});

app.post('/verify', (req, res) => {
    const { token } = req.body;

    // --- MERN-JWT-002: algorithms: ['none'] — signature bypass ---
    const decoded = jwt.verify(token, jwtSecret, { algorithms: ['none', 'HS256'] });

    // --- MERN-JWT-003: jwt.verify() without options (no expiry check) ---
    const decoded2 = jwt.verify(token, jwtSecret);

    res.json(decoded);
});

// -------------------------------------------------------
// User routes — NoSQL injection & mass assignment
// -------------------------------------------------------
const User = mongoose.model('User', new mongoose.Schema({
    username: String,
    password: String,
    isAdmin: Boolean,
}));

app.post('/register', async (req, res) => {
    // --- MERN-NOSQL-003: Mongoose model created directly from req.body ---
    const user = new User(req.body);
    await user.save();
    res.json({ message: 'User created' });
});

app.get('/users/search', async (req, res) => {
    // --- MERN-NOSQL-001: req.query passed directly to find() ---
    const users = await User.find(req.query);
    res.json(users);
});

// -------------------------------------------------------
// Command injection
// -------------------------------------------------------
app.get('/ping', (req, res) => {
    const host = req.query.host;

    // --- MERN-CMDI-001: exec() with user-controlled input ---
    exec(`ping -c 1 ${req.query.host}`, (err, stdout) => {
        res.send(stdout);
    });
});

app.get('/run', (req, res) => {
    const cmd = req.query.cmd;

    // --- MERN-CMDI-003: eval() with req.query ---
    eval(req.query.expression);

    res.send('Done');
});

// -------------------------------------------------------
// Path traversal
// -------------------------------------------------------
app.get('/file', (req, res) => {
    // --- MERN-PATH-001: fs.readFile with user-controlled path ---
    fs.readFile(req.query.filename, 'utf8', (err, data) => {
        if (err) return res.status(404).send('Not found');
        res.send(data);
    });
});

app.get('/download', (req, res) => {
    // --- MERN-PATH-002: path.join with user-controlled segment ---
    const filePath = path.join(__dirname, 'uploads', req.params.filename);
    res.sendFile(filePath);
});

// -------------------------------------------------------
// XSS
// -------------------------------------------------------
app.get('/search', (req, res) => {
    // --- MERN-XSS-004: res.send() with unsanitized req.query ---
    res.send(`<html><body>Results for: ${req.query.q}</body></html>`);
});

// -------------------------------------------------------
// SSRF
// -------------------------------------------------------
app.post('/proxy', async (req, res) => {
    // --- MERN-SSRF-001: axios.get() with user-controlled URL ---
    const response = await axios.get(req.body.url);
    res.json(response.data);
});

// -------------------------------------------------------
// Open redirect
// -------------------------------------------------------
app.get('/redirect', (req, res) => {
    // --- MERN-REDIR-001: res.redirect() with user-controlled URL ---
    res.redirect(req.query.url);
});

// -------------------------------------------------------
// Prototype pollution
// -------------------------------------------------------
app.post('/merge', (req, res) => {
    const config = {};
    // --- MERN-PROTO-001: _.merge() with req.body ---
    _.merge(config, req.body);
    res.json(config);
});

app.post('/extend', (req, res) => {
    // --- MERN-PROTO-002: Object.assign() with req.body ---
    const result = Object.assign({}, req.body);
    res.json(result);
});

// -------------------------------------------------------
// Insecure deserialization
// -------------------------------------------------------
app.post('/deserialize', (req, res) => {
    const serialize = require('node-serialize');
    // --- MERN-DESER-001: node-serialize.unserialize() with req.body ---
    const obj = serialize.unserialize(req.body.data);
    res.json(obj);
});

app.post('/config', (req, res) => {
    // --- MERN-DESER-002: js-yaml YAML.load() with req.body ---
    const config = yaml.load(req.body.config);
    res.json(config);
});

// -------------------------------------------------------
// ReDoS
// -------------------------------------------------------
app.get('/validate', (req, res) => {
    // --- MERN-REDOS-001: RegExp from user input ---
    const pattern = new RegExp(req.query.pattern);
    const result = pattern.test(req.query.input);
    res.json({ match: result });
});

// -------------------------------------------------------
// CORS misconfiguration
// -------------------------------------------------------
// --- MERN-CONF-001: CORS wildcard origin ---
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});

// -------------------------------------------------------
// Hardcoded credentials
// -------------------------------------------------------
// --- MERN-SEC-003: Hardcoded API key ---
const apiKey = 'EXAMPLE_API_KEY_1234567890abcdef1234567890abcdef';
const accessToken = 'EXAMPLE_ACCESS_TOKEN_abcdefghijklmnopqrstuvwxyz1234';

app.listen(3000, () => console.log('Server running on port 3000'));
