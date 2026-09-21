const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const db = require('./db');
const bot = require('./bot');

const app = express();
app.use(cors());
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// Map to keep track of active WebSocket connections
const onlineUsers = new Map(); // username -> socketId
const hiddenOnlineUsers = new Set(); // usernames who opted to hide their online status for privacy

// Helper: Dispatch high-priority push notification via Expo Push Notification Service
async function sendExpoPushNotification(pushToken, title, body, data = {}) {
  if (!pushToken || typeof pushToken !== 'string' || !pushToken.startsWith('ExponentPushToken[')) {
    return;
  }
  try {
    const payload = {
      to: pushToken,
      sound: 'default',
      title,
      body,
      channelId: 'messages',
      priority: 'high',
      badge: 1,
      data
    };
    const response = await fetch('https://exp.host/--/api/v2/push/send', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Accept-encoding': 'gzip, deflate',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload)
    });
    const result = await response.json();
    console.log(`[Push] Expo push notification delivered to ${pushToken}:`, result?.data?.status || result);
  } catch (err) {
    console.error('[Push] Error sending Expo push notification:', err);
  }
}

// --- REST Endpoints ---

// Health check endpoint for Render / Uptime monitors / keep-alive pingers
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', service: 'NosePies E2EE Backend', uptime: process.uptime(), timestamp: Date.now() });
});

app.get('/healthz', (req, res) => {
  res.status(200).send('OK');
});

app.get('/', (req, res) => {
  res.status(200).send('🔒 NosePies E2EE Encrypted Messaging Relay is running.');
});

// Register Expo push token for background/offline delivery
app.post('/api/push-token', async (req, res) => {
  const { username, pushToken } = req.body;
  if (!username || !pushToken) {
    return res.status(400).json({ error: 'Missing username or pushToken' });
  }
  try {
    await db.run('UPDATE users SET push_token = ? WHERE LOWER(username) = ?', [pushToken, username.toLowerCase()]);
    console.log(`[Push] Registered push token for @${username}`);
    res.json({ success: true });
  } catch (err) {
    console.error('[Push] Error saving push token:', err);
    res.status(500).json({ error: err.message });
  }
});

// Register user with device hardware limit & high-entropy connection code
app.post('/api/register', async (req, res) => {
  const { username, authKeyHash, identityPubKey, encryptedPrivKey, prekeys, deviceId } = req.body;

  if (!username || !authKeyHash || !identityPubKey || !encryptedPrivKey) {
    return res.status(400).json({ error: 'Missing required registration fields' });
  }

  const cleanUsername = username.trim().toLowerCase();

  try {
    // 1. Device Hardware Limit Check (Option B: Max 2 accounts per physical device per 30-day rolling window)
    if (deviceId) {
      const deviceCheck = await db.get(
        "SELECT COUNT(*) as count, MIN(created_at) as oldest_creation FROM device_creations WHERE device_id = ? AND created_at >= datetime('now', '-30 days')",
        [deviceId]
      );
      if (deviceCheck && deviceCheck.count >= 2) {
        let daysLeftMsg = 'in a few days';
        if (deviceCheck.oldest_creation) {
          const oldest = new Date(deviceCheck.oldest_creation + 'Z');
          const unlockTime = oldest.getTime() + 30 * 24 * 60 * 60 * 1000;
          const daysLeft = Math.max(1, Math.ceil((unlockTime - Date.now()) / (1000 * 60 * 60 * 24)));
          daysLeftMsg = `in ${daysLeft} day${daysLeft === 1 ? '' : 's'}`;
        }
        return res.status(403).json({
          error: `Device registration limit reached (maximum 2 accounts per 30 days). You can create another account on this device ${daysLeftMsg}.`
        });
      }
    }

    // 2. Check username availability
    const existing = await db.get('SELECT username FROM users WHERE LOWER(username) = ?', [cleanUsername]);
    if (existing) {
      return res.status(400).json({ error: 'Username already taken' });
    }

    // 3. Generate high-entropy cryptographic connection code (e.g. NP-7842-9183)
    let connectionCode = db.generateConnectionCode();
    let codeExists = await db.get('SELECT username FROM users WHERE connection_code = ?', [connectionCode]);
    while (codeExists) {
      connectionCode = db.generateConnectionCode();
      codeExists = await db.get('SELECT username FROM users WHERE connection_code = ?', [connectionCode]);
    }

    // 4. Insert user with device_id and connection_code
    await db.run(
      'INSERT INTO users (username, auth_key_hash, identity_pub_key, encrypted_priv_key, connection_code, device_id) VALUES (?, ?, ?, ?, ?, ?)',
      [cleanUsername, authKeyHash, identityPubKey, encryptedPrivKey, connectionCode, deviceId || null]
    );

    // 5. Record creation event in device_creations for rolling 30-day quota (Option B)
    if (deviceId) {
      await db.run(
        'INSERT INTO device_creations (device_id, username, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)',
        [deviceId, cleanUsername]
      );
    }

    // 6. Insert prekeys if provided
    if (Array.isArray(prekeys)) {
      for (const pk of prekeys) {
        await db.run(
          'INSERT INTO prekeys (username, key_id, public_key) VALUES (?, ?, ?)',
          [cleanUsername, pk.keyId, pk.publicKey]
        );
      }
    }

    console.log(`[DB] Registered user into chat.db: ${cleanUsername} [Code: ${connectionCode}, Device: ${deviceId || 'N/A'}]`);
    res.status(201).json({
      message: 'User registered successfully',
      connectionCode
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Private lookup: Find a user by cryptographic connection code or username
app.get('/api/users/lookup/:query', async (req, res) => {
  const query = req.params.query ? req.params.query.trim() : '';
  if (!query) {
    return res.status(400).json({ error: 'Query parameter required' });
  }

  try {
    const user = await db.get(
      'SELECT username, identity_pub_key, connection_code FROM users WHERE UPPER(connection_code) = ? OR LOWER(username) = ?',
      [query.toUpperCase(), query.toLowerCase()]
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found with this code or username' });
    }

    res.json({
      username: user.username,
      identityPubKey: user.identity_pub_key,
      connectionCode: user.connection_code
    });
  } catch (err) {
    console.error('User lookup error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Login user
app.post('/api/login', async (req, res) => {
  const { username, authKeyHash } = req.body;

  if (!username || !authKeyHash) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  const cleanUsername = username.trim().toLowerCase();

  try {
    const user = await db.get('SELECT auth_key_hash, encrypted_priv_key, connection_code FROM users WHERE LOWER(username) = ?', [cleanUsername]);
    if (!user || user.auth_key_hash !== authKeyHash) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Ensure connection code exists
    let connectionCode = user.connection_code;
    if (!connectionCode) {
      connectionCode = db.generateConnectionCode();
      await db.run('UPDATE users SET connection_code = ? WHERE LOWER(username) = ?', [connectionCode, cleanUsername]);
    }

    res.json({
      encryptedPrivKey: user.encrypted_priv_key,
      connectionCode
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// 1-Tap Revoke & Regenerate Connection Code
app.post('/api/users/reset-code', async (req, res) => {
  const { username, authKeyHash } = req.body;

  if (!username || !authKeyHash) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  const cleanUsername = username.trim().toLowerCase();

  try {
    const user = await db.get('SELECT auth_key_hash FROM users WHERE LOWER(username) = ?', [cleanUsername]);
    if (!user || user.auth_key_hash !== authKeyHash) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Generate fresh high-entropy code
    let connectionCode = db.generateConnectionCode();
    let codeExists = await db.get('SELECT username FROM users WHERE connection_code = ?', [connectionCode]);
    while (codeExists) {
      connectionCode = db.generateConnectionCode();
      codeExists = await db.get('SELECT username FROM users WHERE connection_code = ?', [connectionCode]);
    }

    await db.run('UPDATE users SET connection_code = ? WHERE LOWER(username) = ?', [connectionCode, cleanUsername]);
    console.log(`[DB] Revoked and regenerated code for ${cleanUsername}: ${connectionCode}`);

    res.json({ connectionCode });
  } catch (err) {
    console.error('Reset code error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Permanently Delete Account Endpoint
app.post('/api/users/delete-account', async (req, res) => {
  const { username, authKeyHash } = req.body;

  if (!username || !authKeyHash) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  const cleanUsername = username.trim().toLowerCase();

  try {
    const user = await db.get('SELECT auth_key_hash, device_id FROM users WHERE LOWER(username) = ?', [cleanUsername]);
    if (!user || user.auth_key_hash !== authKeyHash) {
      return res.status(401).json({ error: 'Invalid authentication credentials' });
    }

    // Permanently wipe user identity from database tables
    await db.run('DELETE FROM users WHERE LOWER(username) = ?', [cleanUsername]);
    await db.run('DELETE FROM prekeys WHERE LOWER(username) = ?', [cleanUsername]);
    await db.run('DELETE FROM queued_messages WHERE LOWER(sender) = ? OR LOWER(recipient) = ?', [cleanUsername, cleanUsername]);
    await db.run('DELETE FROM vault_messages WHERE LOWER(sender) = ? OR LOWER(recipient) = ?', [cleanUsername, cleanUsername]);

    console.log(`[DB] Account permanently deleted from chat.db: @${cleanUsername}`);
    res.json({ success: true, message: 'Account permanently deleted' });
  } catch (err) {
    console.error('Delete account error:', err);
    res.status(500).json({ error: 'Database error deleting account' });
  }
});

// Fetch prekey bundle for a user to start an E2EE session
app.get('/api/prekeys/:username', async (req, res) => {
  const { username } = req.params;

  try {
    const user = await db.get('SELECT identity_pub_key FROM users WHERE username = ?', [username]);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get a prekey for this user
    // In a full implementation, we consume a one-time prekey. Here we fetch the first available.
    const prekey = await db.get('SELECT key_id, public_key FROM prekeys WHERE username = ? LIMIT 1', [username]);

    res.json({
      identityPubKey: user.identity_pub_key,
      prekey: prekey ? { keyId: prekey.key_id, publicKey: prekey.public_key } : null
    });
  } catch (err) {
    console.error('Fetch prekeys error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// List all registered users (for contact discovery) with avatar & about
app.get('/api/users', async (req, res) => {
  try {
    const users = await db.all('SELECT username, identity_pub_key, avatar, about FROM users');
    res.json(users);
  } catch (err) {
    console.error('List users error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Lookup a specific user by username (case-insensitive) for contact connection
app.get('/api/users/lookup/:query', async (req, res) => {
  const { query } = req.params;
  try {
    const cleanQuery = query.trim().toLowerCase();
    const user = await db.get(
      'SELECT username, identity_pub_key, avatar, about FROM users WHERE LOWER(username) = LOWER(?)',
      [cleanQuery]
    );
    if (!user) {
      return res.status(404).json({ error: 'No user found with that secret code or username.' });
    }
    res.json({
      username: user.username,
      identityPubKey: user.identity_pub_key,
      avatar: user.avatar || null,
      about: user.about || '🔒 NosePies E2EE Active • PFS Verified'
    });
  } catch (err) {
    console.error('Lookup user error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get detailed profile of a user (WhatsApp-style contact info)
app.get('/api/users/:username/profile', async (req, res) => {
  const { username } = req.params;
  try {
    const user = await db.get(
      'SELECT username, identity_pub_key, avatar, about, created_at FROM users WHERE LOWER(username) = LOWER(?)',
      [username.trim().toLowerCase()]
    );
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({
      username: user.username,
      identityPubKey: user.identity_pub_key,
      avatar: user.avatar || null,
      about: user.about || '🔒 NosePies E2EE Active • PFS Verified',
      createdAt: user.created_at
    });
  } catch (err) {
    console.error('Get profile error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Update authenticated user's profile photo and/or about status
app.post('/api/users/profile', async (req, res) => {
  const { username, authKeyHash, avatar, about } = req.body;
  if (!username || !authKeyHash) {
    return res.status(400).json({ error: 'Username and authKeyHash are required' });
  }

  try {
    const user = await db.get(
      'SELECT username, auth_key_hash FROM users WHERE LOWER(username) = LOWER(?)',
      [username.trim().toLowerCase()]
    );
    if (!user || user.auth_key_hash !== authKeyHash) {
      return res.status(401).json({ error: 'Unauthorized: Invalid authentication credentials' });
    }

    const updates = [];
    const params = [];
    if (avatar !== undefined) {
      updates.push('avatar = ?');
      params.push(avatar);
    }
    if (about !== undefined) {
      updates.push('about = ?');
      params.push(about.trim());
    }

    if (updates.length > 0) {
      params.push(user.username);
      await db.run(`UPDATE users SET ${updates.join(', ')} WHERE username = ?`, params);
    }

    const updatedUser = await db.get(
      'SELECT username, avatar, about FROM users WHERE username = ?',
      [user.username]
    );

    // Broadcast profile update via WebSocket so all contacts reflect the new avatar & bio in real-time
    io.emit('profile_updated', {
      username: user.username,
      avatar: updatedUser.avatar || null,
      about: updatedUser.about || '🔒 NosePies E2EE Active • PFS Verified'
    });

    res.json({
      success: true,
      avatar: updatedUser.avatar || null,
      about: updatedUser.about || '🔒 NosePies E2EE Active • PFS Verified'
    });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Authenticated zero-knowledge vault sync: allows a client to fetch all encrypted messages
// where the user is sender or recipient. Server has zero keys and cannot read content.
app.post('/api/messages/sync', async (req, res) => {
  const { username, authKeyHash } = req.body;
  if (!username || !authKeyHash) {
    return res.status(400).json({ error: 'Missing authentication credentials' });
  }

  const cleanUsername = username.trim().toLowerCase();
  try {
    const user = await db.get('SELECT auth_key_hash FROM users WHERE LOWER(username) = ?', [cleanUsername]);
    if (!user || user.auth_key_hash !== authKeyHash) {
      return res.status(401).json({ error: 'Authentication failed' });
    }

    const messages = await db.all(
      'SELECT id, sender, recipient, encrypted_payload, status, timestamp FROM vault_messages WHERE LOWER(sender) = ? OR LOWER(recipient) = ? ORDER BY timestamp ASC',
      [cleanUsername, cleanUsername]
    );

    res.json({ messages });
  } catch (err) {
    console.error('Vault sync error:', err);
    res.status(500).json({ error: 'Database error fetching message vault' });
  }
});


// --- WebSocket Socket.io Logic ---

io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);

  // User authentication over websocket
  socket.on('authenticate', async ({ username, authKeyHash, showOnlineStatus }) => {
    try {
      const user = await db.get('SELECT auth_key_hash, show_online_status FROM users WHERE username = ?', [username]);
      if (!user || user.auth_key_hash !== authKeyHash) {
        socket.emit('auth_error', { error: 'Authentication failed' });
        socket.disconnect();
        return;
      }

      socket.username = username;
      onlineUsers.set(username, socket.id);
      console.log(`User ${username} authenticated on socket ${socket.id}`);

      // Determine visibility: explicit client param or saved preference in DB (default 1 / true)
      const isVisible = showOnlineStatus !== undefined 
        ? (showOnlineStatus === true) 
        : (user.show_online_status !== 0);

      if (isVisible) {
        hiddenOnlineUsers.delete(username);
        // Broadcast online status change to peers
        io.emit('status_change', { username, status: 'online' });
      } else {
        hiddenOnlineUsers.add(username);
        console.log(`User ${username} connected in Ghost Mode (online status hidden)`);
      }
      
      socket.emit('authenticated', { showOnlineStatus: isVisible });
    } catch (err) {
      console.error('Socket auth error:', err);
      socket.disconnect();
    }
  });

  // Register push token for socket session
  socket.on('register_push_token', async ({ pushToken }) => {
    if (!socket.username || !pushToken) return;
    try {
      await db.run('UPDATE users SET push_token = ? WHERE LOWER(username) = ?', [pushToken, socket.username.toLowerCase()]);
      console.log(`[Push] Socket registered push token for @${socket.username}`);
    } catch (err) {
      console.error('[Push] Socket push token save error:', err);
    }
  });

  // Handle privacy setting for online status
  socket.on('set_online_privacy', async ({ showOnlineStatus }, callback) => {
    if (!socket.username) return;
    const username = socket.username;
    const isVisible = showOnlineStatus !== false;
    try {
      if (isVisible) {
        hiddenOnlineUsers.delete(username);
        await db.run('UPDATE users SET show_online_status = 1 WHERE username = ?', [username]);
        io.emit('status_change', { username, status: 'online' });
        console.log(`User ${username} enabled online status visibility`);
      } else {
        hiddenOnlineUsers.add(username);
        await db.run('UPDATE users SET show_online_status = 0 WHERE username = ?', [username]);
        io.emit('status_change', { username, status: 'offline' });
        console.log(`User ${username} hid online status (Ghost Mode active)`);
      }
      if (callback) callback({ success: true, showOnlineStatus: isVisible });
    } catch (err) {
      console.error('Error updating online status privacy:', err);
      if (callback) callback({ success: false, error: err.message });
    }
  });

  // Handle get queued messages and queued receipts
  socket.on('get_queued_messages', async () => {
    if (!socket.username) return;

    try {
      // 1. Deliver offline messages
      const messages = await db.all(
        'SELECT id, sender, recipient, encrypted_payload, message_id, timestamp, created_at FROM queued_messages WHERE recipient = ? ORDER BY id ASC',
        [socket.username]
      );

      if (messages.length > 0) {
        socket.emit('queued_messages', messages);
        // Delete messages from server once sent to client
        const ids = messages.map(m => m.id);
        await db.run(`DELETE FROM queued_messages WHERE id IN (${ids.map(() => '?').join(',')})`, ids);
        console.log(`Delivered and cleared ${messages.length} queued messages for ${socket.username}`);
      }

      // 2. Deliver offline read and delivered receipts to this user
      const receipts = await db.all(
        'SELECT id, sender, message_id, status FROM queued_receipts WHERE recipient = ? ORDER BY id ASC',
        [socket.username]
      );
      if (receipts && receipts.length > 0) {
        receipts.forEach(r => {
          if (r.status === 'read') {
            socket.emit('message_read', { messageIds: [r.message_id], recipient: r.sender });
          } else if (r.status === 'delivered') {
            socket.emit('message_delivered', { messageId: r.message_id, recipient: r.sender });
          }
        });
        const rIds = receipts.map(r => r.id);
        await db.run(`DELETE FROM queued_receipts WHERE id IN (${rIds.map(() => '?').join(',')})`, rIds);
        console.log(`Delivered and cleared ${receipts.length} queued receipts for ${socket.username}`);
      }
    } catch (err) {
      console.error('Fetch queued messages error:', err);
    }
  });

  // Check online status of users
  socket.on('check_online', (usernames, callback) => {
    const statuses = {};
    usernames.forEach(name => {
      if (bot.isBot(name)) {
        statuses[name] = 'online';
      } else if (hiddenOnlineUsers.has(name)) {
        statuses[name] = 'offline';
      } else {
        statuses[name] = onlineUsers.has(name) ? 'online' : 'offline';
      }
    });
    callback(statuses);
  });

  // Relay real-time E2E encrypted message
  socket.on('send_message', async ({ messageId, recipient, encryptedPayload }) => {
    if (!socket.username) return;

    try {
      const finalMsgId = messageId || (Date.now().toString() + '_' + Math.random().toString(36).substr(2, 6));
      const nowIso = new Date().toISOString();
      const isRecipientBot = bot.isBot(recipient);
      const isRecipientOnline = onlineUsers.has(recipient);
      const initialStatus = isRecipientBot ? 'read' : (isRecipientOnline ? 'delivered' : 'sent');

      // Always persist opaque ciphertext with initial delivery/read status in vault
      db.run(
        'INSERT OR REPLACE INTO vault_messages (id, sender, recipient, encrypted_payload, status, timestamp) VALUES (?, ?, ?, ?, ?, ?)',
        [finalMsgId, socket.username, recipient, encryptedPayload, initialStatus, nowIso]
      ).catch(err => console.error('Error saving to vault_messages:', err));

      // Check if message is directed to Bot
      if (isRecipientBot) {
        console.log(`Routing E2E encrypted message from ${socket.username} to NosePies Bot`);
        bot.handleBotMessage({
          messageId: finalMsgId,
          sender: socket.username,
          encryptedPayloadStr: encryptedPayload,
          io,
          onlineUsers
        });
        return;
      }

      const recipientSocketId = onlineUsers.get(recipient);
      
      if (recipientSocketId) {
        // Recipient is online, relay instantly
        io.to(recipientSocketId).emit('receive_message', {
          messageId: finalMsgId,
          sender: socket.username,
          encryptedPayload,
          timestamp: nowIso
        });
        // Immediately acknowledge delivery to sender
        socket.emit('message_delivered', { messageId: finalMsgId, recipient });
        console.log(`Relayed E2E message from ${socket.username} to ${recipient} (online)`);
      } else {
        // Recipient is offline, queue message
        await db.run(
          'INSERT INTO queued_messages (sender, recipient, encrypted_payload, message_id, timestamp) VALUES (?, ?, ?, ?, ?)',
          [socket.username, recipient, encryptedPayload, finalMsgId, nowIso]
        );
        console.log(`Queued E2E message from ${socket.username} to ${recipient} (offline, id: ${finalMsgId})`);

        // Send Expo push notification if recipient has registered a push token
        db.get('SELECT push_token FROM users WHERE LOWER(username) = ?', [recipient.toLowerCase()])
          .then(recipientUser => {
            if (recipientUser && recipientUser.push_token) {
              sendExpoPushNotification(
                recipientUser.push_token,
                `@${socket.username}`,
                '🔒 New encrypted message',
                { sender: socket.username }
              );
            }
          })
          .catch(err => console.error('[Push] Failed to query recipient push token:', err));
      }
    } catch (err) {
      console.error('Send message error:', err);
    }
  });

  // Client requests removal of a message from the persistent vault
  socket.on('delete_message_vault', async ({ messageId }) => {
    if (!socket.username || !messageId) return;
    try {
      await db.run(
        'DELETE FROM vault_messages WHERE id = ? AND (LOWER(sender) = ? OR LOWER(recipient) = ?)',
        [messageId, socket.username.toLowerCase(), socket.username.toLowerCase()]
      );
    } catch (_) {}
  });

  // Client requests clearing an entire chat thread from the persistent vault
  socket.on('clear_conversation_vault', async ({ contact }) => {
    if (!socket.username || !contact) return;
    try {
      const u = socket.username.toLowerCase();
      const c = contact.toLowerCase();
      await db.run(
        'DELETE FROM vault_messages WHERE (LOWER(sender) = ? AND LOWER(recipient) = ?) OR (LOWER(sender) = ? AND LOWER(recipient) = ?)',
        [u, c, c, u]
      );
    } catch (_) {}
  });

  // Client confirms message received/delivered
  socket.on('message_delivered', async ({ messageId, sender }) => {
    if (!sender) return;
    if (messageId) {
      await db.run("UPDATE vault_messages SET status = 'delivered' WHERE id = ? AND status != 'read'", [messageId]).catch(() => {});
    }
    const senderSocketId = onlineUsers.get(sender);
    if (senderSocketId) {
      io.to(senderSocketId).emit('message_delivered', { messageId, recipient: socket.username });
    } else if (messageId) {
      // Queue delivery receipt for offline sender
      await db.run(
        "INSERT INTO queued_receipts (recipient, sender, message_id, status) VALUES (?, ?, ?, 'delivered')",
        [sender, socket.username, messageId]
      ).catch(() => {});
    }
  });

  // Client confirms message read / viewed
  socket.on('message_read', async ({ messageIds, sender }) => {
    if (!sender) return;
    if (Array.isArray(messageIds) && messageIds.length > 0) {
      const placeholders = messageIds.map(() => '?').join(',');
      await db.run(
        `UPDATE vault_messages SET status = 'read' WHERE id IN (${placeholders})`,
        messageIds
      ).catch(() => {});
    } else {
      await db.run(
        "UPDATE vault_messages SET status = 'read' WHERE LOWER(sender) = LOWER(?) AND LOWER(recipient) = LOWER(?)",
        [sender, socket.username]
      ).catch(() => {});
    }

    const senderSocketId = onlineUsers.get(sender);
    if (senderSocketId) {
      io.to(senderSocketId).emit('message_read', { messageIds, recipient: socket.username });
    } else if (Array.isArray(messageIds) && messageIds.length > 0) {
      // Queue read receipt for offline sender
      for (const mid of messageIds) {
        await db.run(
          "INSERT INTO queued_receipts (recipient, sender, message_id, status) VALUES (?, ?, ?, 'read')",
          [sender, socket.username, mid]
        ).catch(() => {});
      }
    }
  });

  // Typing indicators
  socket.on('typing_start', ({ recipient }) => {
    if (!recipient) return;
    const recipientSocketId = onlineUsers.get(recipient);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('typing_status', { sender: socket.username, isTyping: true });
    }
  });

  socket.on('typing_stop', ({ recipient }) => {
    if (!recipient) return;
    const recipientSocketId = onlineUsers.get(recipient);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('typing_status', { sender: socket.username, isTyping: false });
    }
  });

  // Client toggles/sends an emoji reaction to a message
  socket.on('message_reaction', async ({ messageId, recipient, emoji }) => {
    if (!socket.username || !recipient || !messageId) return;

    if (recipient.toLowerCase() === bot.BOT_USERNAME.toLowerCase()) {
      // Test bot responds with an appreciative reaction
      const botEmojis = ['❤️', '🔥', '👏', '💯', '✨', '👍'];
      const randomBotEmoji = botEmojis[Math.floor(Math.random() * botEmojis.length)];
      setTimeout(() => {
        socket.emit('message_reaction', {
          messageId,
          sender: bot.BOT_USERNAME,
          emoji: randomBotEmoji
        });
      }, 700);
      return;
    }

    const recipientSocketId = onlineUsers.get(recipient.toLowerCase());
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('message_reaction', {
        messageId,
        sender: socket.username,
        emoji
      });
    }
  });

  socket.on('disconnect', () => {
    if (socket.username) {
      const username = socket.username;
      onlineUsers.delete(username);
      hiddenOnlineUsers.delete(username);
      console.log(`User ${username} disconnected`);
      // Broadcast offline status change
      io.emit('status_change', { username, status: 'offline' });
    }
  });
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, '0.0.0.0', async () => {
  console.log(`E2EE Chat backend running on http://localhost:${PORT}`);
  await bot.initBot();
});
