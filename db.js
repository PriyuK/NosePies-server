const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'chat.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database at:', dbPath);
  }
});

// Initialize database schema
db.serialize(() => {
  // Ensure maximum persistence and durability
  db.run('PRAGMA journal_mode = WAL;');
  db.run('PRAGMA synchronous = NORMAL;');

  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      auth_key_hash TEXT NOT NULL,
      identity_pub_key TEXT NOT NULL,
      encrypted_priv_key TEXT NOT NULL,
      show_online_status INTEGER DEFAULT 1,
      push_token TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  db.run("ALTER TABLE users ADD COLUMN push_token TEXT", () => {});

  // PreKeys table for X3DH (offline key exchange initialization)
  db.run(`
    CREATE TABLE IF NOT EXISTS prekeys (
      username TEXT,
      key_id TEXT NOT NULL,
      public_key TEXT NOT NULL,
      PRIMARY KEY (username, key_id),
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    )
  `);

  // Queued offline messages table
  db.run(`
    CREATE TABLE IF NOT EXISTS queued_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender TEXT NOT NULL,
      recipient TEXT NOT NULL,
      encrypted_payload TEXT NOT NULL,
      message_id TEXT,
      timestamp TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (sender) REFERENCES users(username),
      FOREIGN KEY (recipient) REFERENCES users(username)
    )
  `);
  db.run("ALTER TABLE queued_messages ADD COLUMN message_id TEXT", () => {});
  db.run("ALTER TABLE queued_messages ADD COLUMN timestamp TEXT", () => {});

  // Zero-Knowledge Encrypted Message Vault (stores ONLY opaque ciphertext, server has zero keys)
  db.run(`
    CREATE TABLE IF NOT EXISTS vault_messages (
      id TEXT PRIMARY KEY,
      sender TEXT NOT NULL,
      recipient TEXT NOT NULL,
      encrypted_payload TEXT NOT NULL,
      status TEXT DEFAULT 'sent',
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  db.run("CREATE INDEX IF NOT EXISTS idx_vault_sender ON vault_messages(sender)", () => {});
  db.run("CREATE INDEX IF NOT EXISTS idx_vault_recipient ON vault_messages(recipient)", () => {});
  db.run("CREATE INDEX IF NOT EXISTS idx_vault_participants ON vault_messages(sender, recipient)", () => {});
  db.run("ALTER TABLE vault_messages ADD COLUMN status TEXT DEFAULT 'sent'", () => {});

  // Queued delivery and read receipts table for offline recipients
  db.run(`
    CREATE TABLE IF NOT EXISTS queued_receipts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      recipient TEXT NOT NULL,
      sender TEXT NOT NULL,
      message_id TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  db.run("CREATE INDEX IF NOT EXISTS idx_receipts_recipient ON queued_receipts(recipient)", () => {});

  // Automatically mark bot interactions and existing vault messages as 'read'
  db.run("UPDATE vault_messages SET status = 'read' WHERE recipient = 'nosepies_bot' OR sender = 'nosepies_bot'", () => {});

  // Safe column migrations for existing users table
  db.run("ALTER TABLE users ADD COLUMN connection_code TEXT", () => {});
  db.run("ALTER TABLE users ADD COLUMN device_id TEXT", () => {});
  db.run("ALTER TABLE users ADD COLUMN avatar TEXT", () => {});
  db.run("ALTER TABLE users ADD COLUMN about TEXT DEFAULT '🔒 NosePies E2EE Active • PFS Verified'", () => {});
  db.run("ALTER TABLE users ADD COLUMN show_online_status INTEGER DEFAULT 1", () => {});
  db.run("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_connection_code ON users(connection_code)", () => {});
  db.run("CREATE INDEX IF NOT EXISTS idx_users_device_id ON users(device_id)", () => {});

  // Device creations audit table for rolling 30-day limits (Option B)
  db.run(`
    CREATE TABLE IF NOT EXISTS device_creations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id TEXT NOT NULL,
      username TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  db.run("CREATE INDEX IF NOT EXISTS idx_device_creations_dev_time ON device_creations(device_id, created_at)", () => {});

  // Backfill connection codes for existing users if any are missing
  db.all("SELECT username FROM users WHERE connection_code IS NULL OR connection_code = ''", (err, rows) => {
    if (!err && Array.isArray(rows)) {
      rows.forEach(r => {
        const code = `NP-${Math.floor(1000 + Math.random() * 9000)}-${Math.floor(1000 + Math.random() * 9000)}`;
        db.run("UPDATE users SET connection_code = ? WHERE username = ?", [code, r.username]);
      });
    }
  });
});

function generateConnectionCode() {
  const p1 = Math.floor(1000 + Math.random() * 9000);
  const p2 = Math.floor(1000 + Math.random() * 9000);
  return `NP-${p1}-${p2}`;
}

module.exports = {
  // Helper to run query and return a promise
  run(sql, params = []) {
    return new Promise((resolve, reject) => {
      db.run(sql, params, function (err) {
        if (err) reject(err);
        else resolve({ lastID: this.lastID, changes: this.changes });
      });
    });
  },

  // Helper to get first row
  get(sql, params = []) {
    return new Promise((resolve, reject) => {
      db.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  },

  // Helper to get all rows
  all(sql, params = []) {
    return new Promise((resolve, reject) => {
      db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  },

  generateConnectionCode
};
