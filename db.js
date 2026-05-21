const Database = require('better-sqlite3');
const fs = require('fs');
require('dotenv').config();

// Auto-create database folder if it doesn't exist
if (!fs.existsSync('./database')) {
    fs.mkdirSync('./database');
}

const db = new Database(process.env.DB_PATH);

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Create tables
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        username     TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        key_salt     TEXT NOT NULL,
        created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS notes (
        id                   TEXT PRIMARY KEY,
        username             TEXT NOT NULL,
        title_ciphertext     TEXT,
        content_ciphertext   TEXT,
        wrapped_note_key     TEXT,
        updated_at           INTEGER NOT NULL,
        deleted              INTEGER DEFAULT 0,
        FOREIGN KEY (username) REFERENCES users(username)
    );
`);

console.log('Database initialized successfully');

module.exports = db;