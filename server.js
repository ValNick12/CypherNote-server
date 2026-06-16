const express = require('express');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const db = require('./db');
const authenticateToken = require('./middleware/auth');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// ─────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────
app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

// ─────────────────────────────────────────
// AUTH — REGISTER
// ─────────────────────────────────────────
app.post('/auth/register', (req, res) => {
    const { username, passwordHash } = req.body; // App sends pre-hashed pass

    // Server only checks uniqueness
    const existing = db.prepare('SELECT username FROM users WHERE username = ?').get(username);
    if (existing) {
        return res.status(409).json({ error: 'User already exists' });
    }

    // Server generates a salt for the app to use in encryption key derivation
    const keySalt = uuidv4().replace(/-/g, '');

    db.prepare(`
        INSERT INTO users (username, password_hash, key_salt)
        VALUES (?, ?, ?)
    `).run(username, passwordHash, keySalt);

    const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '30d' });

    res.status(201).json({ token, keySalt });
});

// ─────────────────────────────────────────
// AUTH — LOGIN
// ─────────────────────────────────────────
app.post('/auth/login', (req, res) => {
    const { username, passwordHash } = req.body;

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

    // Simple string comparison because app already provided the hash
    if (!user || user.password_hash !== passwordHash) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '30d' });

    res.json({ token, keySalt: user.key_salt });
});

// ─────────────────────────────────────────
// NOTES — GET ALL (for current user)
// ─────────────────────────────────────────

app.get('/notes', authenticateToken, (req, res) => {
    const notes = db.prepare(`  
        SELECT * FROM notes  
        WHERE username = ?  
        ORDER BY updated_at DESC  
    `).all(req.username);

    res.json({ notes });
});

// ─────────────────────────────────────────
// NOTES — UPSERT (create or update)
// ─────────────────────────────────────────

app.post('/notes/upsert', authenticateToken, (req, res) => {
    const {
        id,
        titleCiphertext,
        contentCiphertext,
        wrappedNoteKey,
        updatedAt
    } = req.body;

    if (!id || !updatedAt) {
        return res.status(400).json({ error: 'Note id and updatedAt are required' });
    }

    // Check if note already exists on server
    const existing = db.prepare('SELECT id, updated_at FROM notes WHERE id = ?').get(id);

    if (!existing) {
        // If note does not exist — insert it
        db.prepare(`
            INSERT INTO notes (id, username, title_ciphertext, content_ciphertext, wrapped_note_key, updated_at, deleted)
            VALUES (?, ?, ?, ?, ?, ?, 0)
        `).run(id, req.username, titleCiphertext, contentCiphertext, wrappedNoteKey, updatedAt);

        return res.status(201).json({ message: 'Note created', id });
    }

    // Note exists — apply latest write wins
    if (updatedAt >= existing.updated_at) {
        db.prepare(`
            UPDATE notes
            SET title_ciphertext = ?,
                content_ciphertext = ?,
                wrapped_note_key = ?,
                updated_at = ?,
                deleted = 0
            WHERE id = ? AND username = ?
        `).run(titleCiphertext, contentCiphertext, wrappedNoteKey, updatedAt, id, req.username);

        return res.json({ message: 'Note updated', id });
    }

    // Incoming note is older — ignore it
    return res.json({ message: 'Note ignored, server has newer version', id });
});

// ─────────────────────────────────────────
// NOTES — SOFT DELETE
// ─────────────────────────────────────────

app.post('/notes/delete', authenticateToken, (req, res) => {
    const { id, updatedAt } = req.body;

    if (!id || !updatedAt) {
        return res.status(400).json({ error: 'Note id and updatedAt are required' });
    }

    const existing = db.prepare('SELECT id, updated_at FROM notes WHERE id = ? AND username = ?').get(id, req.username);

    if (!existing) {
        return res.status(404).json({ error: 'Note not found' });
    }

    // Only delete if incoming timestamp is newer or equal
    if (updatedAt >= existing.updated_at) {
        db.prepare(`
            UPDATE notes
            SET deleted = 1,
                updated_at = ?
            WHERE id = ? AND username = ?
        `).run(updatedAt, id, req.username);

        return res.json({ message: 'Note marked as deleted', id });
    }

    return res.json({ message: 'Delete ignored, server has newer version', id });
});

// ─────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
    console.log(`CipherNote sync server running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
});