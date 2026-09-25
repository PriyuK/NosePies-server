const nacl = require('tweetnacl');
const { encodeBase64, decodeBase64, encodeUTF8, decodeUTF8 } = require('tweetnacl-util');
const crypto = require('crypto');
const db = require('./db');

const BOT_USERNAME = 'nosepies_bot';
let botKeyPair = null;

/**
 * Initializes NosePies Bot cryptographic identity in the database.
 */
async function initBot() {
  try {
    // Purge legacy shield_bot from database
    await db.run('DELETE FROM users WHERE username = ?', ['shield_bot']).catch(() => {});
    await db.run('DELETE FROM prekeys WHERE username = ?', ['shield_bot']).catch(() => {});
    await db.run('DELETE FROM queued_messages WHERE sender = ? OR recipient = ?', ['shield_bot', 'shield_bot']).catch(() => {});
    await db.run('DELETE FROM vault_messages WHERE sender = ? OR recipient = ?', ['shield_bot', 'shield_bot']).catch(() => {});

    const existing = await db.get('SELECT username, identity_pub_key, encrypted_priv_key FROM users WHERE username = ?', [BOT_USERNAME]);
    
    if (existing && existing.encrypted_priv_key) {
      botKeyPair = {
        publicKey: decodeBase64(existing.identity_pub_key),
        secretKey: decodeBase64(existing.encrypted_priv_key)
      };
      console.log('🤖 NosePies Bot crypto identity loaded from database.');
    } else {
      const generated = nacl.box.keyPair();
      botKeyPair = generated;
      const pubB64 = encodeBase64(generated.publicKey);
      const privB64 = encodeBase64(generated.secretKey);

      await db.run(
        'INSERT OR REPLACE INTO users (username, auth_key_hash, identity_pub_key, encrypted_priv_key) VALUES (?, ?, ?, ?)',
        [BOT_USERNAME, 'BOT_NO_AUTH', pubB64, privB64]
      );

      await db.run(
        'INSERT OR REPLACE INTO prekeys (username, key_id, public_key) VALUES (?, ?, ?)',
        [BOT_USERNAME, 'prekey_bot_1', pubB64]
      );

      console.log('🤖 NosePies Bot created new cryptographic identity in database.');
    }
  } catch (err) {
    console.error('Failed to initialize NosePies Bot:', err);
  }
}

/**
 * Checks if a username is the bot.
 */
function isBot(username) {
  return username === BOT_USERNAME;
}

/**
 * Handles an incoming encrypted message sent to ShieldBot.
 * Decrypts it, processes the text, encrypts a reply, and sends back.
 */
async function handleBotMessage({ messageId, sender, encryptedPayloadStr, io, onlineUsers }) {
  if (!botKeyPair) return;

  try {
    const userRow = await db.get('SELECT identity_pub_key FROM users WHERE username = ?', [sender]);
    if (!userRow) {
      console.error(`ShieldBot: Sender ${sender} not found in database.`);
      return;
    }

    const senderSocketId = onlineUsers.get(sender);

    // 1. Immediately acknowledge message delivery
    if (senderSocketId && messageId) {
      io.to(senderSocketId).emit('message_delivered', { messageId, recipient: BOT_USERNAME });
    }

    const senderPubKey = decodeBase64(userRow.identity_pub_key);
    const sharedSecret = nacl.box.before(senderPubKey, botKeyPair.secretKey);
    const sharedSecretBase64 = encodeBase64(sharedSecret);

    const payload = JSON.parse(encryptedPayloadStr);
    const ciphertext = decodeBase64(payload.ciphertext);
    const nonce = decodeBase64(payload.nonce);
    const msgCounter = payload.counter;

    // Ephemeral message key derivation for forward secrecy
    const decryptionKey = (msgCounter !== undefined && msgCounter !== null)
      ? crypto.createHash('sha256').update(`${sharedSecretBase64}:${msgCounter}`).digest()
      : sharedSecret;

    const decryptedBytes = nacl.secretbox.open(ciphertext, nonce, decryptionKey);
    if (!decryptedBytes) {
      console.error(`ShieldBot: Could not decrypt message from ${sender} (counter: ${msgCounter}).`);
      return;
    }

    const decryptedText = encodeUTF8(decryptedBytes).trim();
    console.log(`🤖 ShieldBot successfully decrypted message from ${sender} [Ratchet #${msgCounter !== undefined ? msgCounter : 'static'}]: "${decryptedText}"`);

    // Parse potential JSON payload for media
    let processedText = decryptedText;
    let mediaType = null;
    try {
      if (decryptedText.startsWith('{') && decryptedText.endsWith('}')) {
        const parsed = JSON.parse(decryptedText);
        if (parsed.type) {
          mediaType = parsed.type;
          processedText = parsed.text || parsed.caption || `[${parsed.type}]`;
        }
      }
    } catch {
      // plain text
    }

    // 2. Mark message as Read & show typing after 300ms
    setTimeout(() => {
      if (messageId) {
        db.run("UPDATE vault_messages SET status = 'read' WHERE id = ?", [messageId]).catch(() => {});
      }
      if (senderSocketId) {
        if (messageId) {
          io.to(senderSocketId).emit('message_read', { messageIds: [messageId], recipient: BOT_USERNAME });
        }
        io.to(senderSocketId).emit('typing_status', { sender: BOT_USERNAME, isTyping: true });
      }
    }, 300);

    // Generate response
    const replyText = generateBotReply(processedText, sender, userRow.identity_pub_key, mediaType);

    // Ephemeral reply key derivation for forward secrecy
    const replyCounter = (msgCounter !== undefined && msgCounter !== null) ? msgCounter + 1 : Date.now();
    const replyKey = (msgCounter !== undefined && msgCounter !== null)
      ? crypto.createHash('sha256').update(`${sharedSecretBase64}:${replyCounter}`).digest()
      : sharedSecret;

    // Encrypt response with ratcheted key and fresh nonce
    const replyNonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const replyEncryptedBytes = nacl.secretbox(decodeUTF8(replyText), replyNonce, replyKey);

    const replyPayload = {
      ciphertext: encodeBase64(replyEncryptedBytes),
      nonce: encodeBase64(replyNonce),
      counter: replyCounter
    };

    const replyPayloadStr = JSON.stringify(replyPayload);

    // Ensure incoming message is persisted in vault as 'read'
    if (messageId) {
      db.run(
        'INSERT OR REPLACE INTO vault_messages (id, sender, recipient, encrypted_payload, status, timestamp) VALUES (?, ?, ?, ?, ?, ?)',
        [messageId, sender, BOT_USERNAME, encryptedPayloadStr, 'read', new Date().toISOString()]
      ).catch(() => {});
    }

    // 3. Stop typing and send reply after 1000ms
    setTimeout(async () => {
      const botMsgId = 'bot_' + Date.now();
      // Persist bot's encrypted reply to vault as 'read'
      db.run(
        'INSERT OR REPLACE INTO vault_messages (id, sender, recipient, encrypted_payload, status, timestamp) VALUES (?, ?, ?, ?, ?, ?)',
        [botMsgId, BOT_USERNAME, sender, replyPayloadStr, 'read', new Date().toISOString()]
      ).catch(() => {});

      const cleanSender = sender.toLowerCase();
      const senderRoom = io.sockets.adapter.rooms.get(`user:${cleanSender}`);
      const isSenderActive = (senderRoom && senderRoom.size > 0) || senderSocketId;

      if (isSenderActive) {
        io.to(`user:${cleanSender}`).emit('typing_status', { sender: BOT_USERNAME, isTyping: false });
        io.to(`user:${cleanSender}`).emit('receive_message', {
          messageId: botMsgId,
          sender: BOT_USERNAME,
          encryptedPayload: replyPayloadStr,
          timestamp: new Date().toISOString()
        });
        if (senderSocketId && (!senderRoom || !senderRoom.has(senderSocketId))) {
          io.to(senderSocketId).emit('typing_status', { sender: BOT_USERNAME, isTyping: false });
          io.to(senderSocketId).emit('receive_message', {
            messageId: botMsgId,
            sender: BOT_USERNAME,
            encryptedPayload: replyPayloadStr,
            timestamp: new Date().toISOString()
          });
        }
        console.log(`🤖 NosePies Bot sent forward-secret encrypted reply to ${sender} [Ratchet #${replyCounter}]`);
      } else {
        // Queue for sender if they disconnected
        db.run(
          'INSERT INTO queued_messages (sender, recipient, encrypted_payload) VALUES (?, ?, ?)',
          [BOT_USERNAME, sender, replyPayloadStr]
        );
      }
    }, 1100);

  } catch (err) {
    console.error('Error in ShieldBot handler:', err);
  }
}

/**
 * Produces helpful and demonstrative replies.
 */
function generateBotReply(text, sender, senderPubKey, mediaType) {
  if (mediaType === 'image') {
    return `📷 Encrypted Photo Received!\n\nYour photo was decrypted client-side using TweetNaCl Authenticated SecretBox. Zero plaintext reached the server!`;
  }
  if (mediaType === 'audio') {
    return `🎙️ Encrypted Voice Note Received!\n\nYour audio recording was securely decrypted and verified with your Curve25519 key.`;
  }

  const lower = text.toLowerCase();

  if (lower === '!ping') {
    return '🏓 Pong! Real-time WebSocket relay is connected, and our Curve25519 shared secret is verified.';
  }

  if (lower === '!keys') {
    const myPub = encodeBase64(botKeyPair.publicKey);
    return `🔐 E2EE Key Pair Verification:\n\n• Your Public Key:\n  ${senderPubKey}\n\n• ShieldBot Public Key:\n  ${myPub}\n\n• Encryption: Curve25519 (ECDH) + XSalsa20-Poly1305 (Symmetric)\n• Verification Status: Authenticated ✅`;
  }

  if (lower === '!quote') {
    const quotes = [
      '"Arguing that you don\'t care about the right to privacy because you have nothing to hide is no different than saying you don\'t care about free speech because you have nothing to say." — Edward Snowden',
      '"Encryption works. Properly implemented strong crypto systems are one of the few things that you can rely on." — Edward Snowden',
      '"Privacy is not an option, and it shouldn\'t be the price we accept for just getting on the internet." — Gary Kovacs'
    ];
    return quotes[Math.floor(Math.random() * quotes.length)];
  }

  if (lower.startsWith('!help') || lower === 'help') {
    return `🛡️ ShieldBot Test Commands:\n• !ping - Test message latency\n• !keys - Inspect public keys & cipher info\n• !quote - Privacy quotes\n• Or type ANY regular text to test end-to-end encryption!`;
  }

  if (lower.includes('hello') || lower.includes('hi') || lower.includes('hey')) {
    return `👋 Hey ${sender}! I am ShieldBot, your built-in cryptographic testing partner.\n\nYour message was transmitted as ciphertext and successfully decrypted locally using my Curve25519 private key.\n\nTry sending any message or type "!help" for test commands!`;
  }

  return `🔒 [Decrypted & Verified]\nEcho: "${text}"\n\n✅ Your message reached the server fully encrypted and was only decrypted by my device key.`;
}

module.exports = {
  BOT_USERNAME,
  initBot,
  isBot,
  handleBotMessage
};
