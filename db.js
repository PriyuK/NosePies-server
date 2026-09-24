const path = require('path');

const isTurso = !!process.env.TURSO_DATABASE_URL;

let runQuery;
let getQuery;
let allQuery;

function generateConnectionCode() {
  const p1 = Math.floor(1000 + Math.random() * 9000);
  const p2 = Math.floor(1000 + Math.random() * 9000);
  return `NP-${p1}-${p2}`;
}

const schemaQueries = [
  `CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    auth_key_hash TEXT NOT NULL,
    identity_pub_key TEXT NOT NULL,
    encrypted_priv_key TEXT NOT NULL,
    show_online_status INTEGER DEFAULT 1,
    push_token TEXT,
    connection_code TEXT,
    device_id TEXT,
    avatar TEXT,
    about TEXT DEFAULT '🔒 NosePies E2EE Active • PFS Verified',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_users_connection_code ON users(connection_code)`,
  `CREATE INDEX IF NOT EXISTS idx_users_device_id ON users(device_id)`,

  `CREATE TABLE IF NOT EXISTS prekeys (
    username TEXT,
    key_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    PRIMARY KEY (username, key_id),
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
  )`,

  `CREATE TABLE IF NOT EXISTS queued_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    encrypted_payload TEXT NOT NULL,
    message_id TEXT,
    timestamp TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS vault_messages (
    id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    encrypted_payload TEXT NOT NULL,
    status TEXT DEFAULT 'sent',
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE INDEX IF NOT EXISTS idx_vault_sender ON vault_messages(sender)`,
  `CREATE INDEX IF NOT EXISTS idx_vault_recipient ON vault_messages(recipient)`,
  `CREATE INDEX IF NOT EXISTS idx_vault_participants ON vault_messages(sender, recipient)`,

  `CREATE TABLE IF NOT EXISTS queued_receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT NOT NULL,
    sender TEXT NOT NULL,
    message_id TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE INDEX IF NOT EXISTS idx_receipts_recipient ON queued_receipts(recipient)`,

  `CREATE TABLE IF NOT EXISTS device_creations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    username TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE INDEX IF NOT EXISTS idx_device_creations_dev_time ON device_creations(device_id, created_at)`,

  `CREATE TABLE IF NOT EXISTS trusted_recovery (
    owner_username TEXT PRIMARY KEY,
    contact_username TEXT NOT NULL,
    encrypted_priv_key TEXT NOT NULL,
    contact_encrypted_secret TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE INDEX IF NOT EXISTS idx_trusted_recovery_contact ON trusted_recovery(contact_username)`,

  `CREATE TABLE IF NOT EXISTS recovery_requests (
    request_id TEXT PRIMARY KEY,
    requester TEXT NOT NULL,
    contact TEXT NOT NULL,
    code_encrypted_secret TEXT,
    code_hash TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
  )`,
  `CREATE INDEX IF NOT EXISTS idx_recovery_requests_contact ON recovery_requests(contact, status)`,
  `CREATE INDEX IF NOT EXISTS idx_recovery_requests_req ON recovery_requests(requester, status)`
];

if (isTurso) {
  console.log('⚡ Initializing Turso Cloud SQLite database (@libsql/client)...');
  const { createClient } = require('@libsql/client');
  const client = createClient({
    url: process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN
  });

  runQuery = async (sql, params = []) => {
    const res = await client.execute({ sql, args: params });
    return { lastID: res.lastInsertRowid, changes: res.rowsAffected };
  };

  getQuery = async (sql, params = []) => {
    const res = await client.execute({ sql, args: params });
    if (!res.rows || res.rows.length === 0) return null;
    return res.rows[0];
  };

  allQuery = async (sql, params = []) => {
    const res = await client.execute({ sql, args: params });
    return res.rows || [];
  };

  // Initialize schema on Turso
  (async () => {
    try {
      for (const q of schemaQueries) {
        await client.execute(q);
      }
      try {
        await client.execute("ALTER TABLE users ADD COLUMN recovery_encrypted_priv_key TEXT");
      } catch (_) {}
      console.log('✅ Turso Cloud SQLite schema initialized and persistent.');
    } catch (err) {
      console.error('Error initializing Turso schema:', err);
    }
  })();
} else {
  // Fallback to local SQLite3 database file
  const sqlite3 = require('sqlite3').verbose();
  const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'chat.db');
  const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
      console.error('Error opening local database:', err);
    } else {
      console.log('Connected to local SQLite database at:', dbPath);
    }
  });

  db.serialize(() => {
    db.run('PRAGMA journal_mode = WAL;');
    db.run('PRAGMA synchronous = NORMAL;');
    for (const q of schemaQueries) {
      db.run(q, () => {});
    }
    // Safe column migrations
    db.run("ALTER TABLE users ADD COLUMN push_token TEXT", () => {});
    db.run("ALTER TABLE users ADD COLUMN connection_code TEXT", () => {});
    db.run("ALTER TABLE users ADD COLUMN device_id TEXT", () => {});
    db.run("ALTER TABLE users ADD COLUMN avatar TEXT", () => {});
    db.run("ALTER TABLE users ADD COLUMN about TEXT DEFAULT '🔒 NosePies E2EE Active • PFS Verified'", () => {});
    db.run("ALTER TABLE users ADD COLUMN show_online_status INTEGER DEFAULT 1", () => {});
    db.run("ALTER TABLE users ADD COLUMN recovery_encrypted_priv_key TEXT", () => {});
    db.run("ALTER TABLE queued_messages ADD COLUMN message_id TEXT", () => {});
    db.run("ALTER TABLE queued_messages ADD COLUMN timestamp TEXT", () => {});
    db.run("ALTER TABLE vault_messages ADD COLUMN status TEXT DEFAULT 'sent'", () => {});
  });

  runQuery = (sql, params = []) => {
    return new Promise((resolve, reject) => {
      db.run(sql, params, function (err) {
        if (err) reject(err);
        else resolve({ lastID: this.lastID, changes: this.changes });
      });
    });
  };

  getQuery = (sql, params = []) => {
    return new Promise((resolve, reject) => {
      db.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  };

  allQuery = (sql, params = []) => {
    return new Promise((resolve, reject) => {
      db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  };
}

module.exports = {
  run: (sql, params) => runQuery(sql, params),
  get: (sql, params) => getQuery(sql, params),
  all: (sql, params) => allQuery(sql, params),
  generateConnectionCode
};
