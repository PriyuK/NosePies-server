# NosePies E2EE Backend Server

Zero-Knowledge End-to-End Encrypted Messaging Relay & Vault for NosePies.

## Features
- **Zero-Knowledge Relay**: The server only relays opaque encrypted ciphertexts; keys never leave client devices.
- **X3DH PreKey Bundle Support**: Offline asynchronous key agreement.
- **WebSocket Protocol**: Real-time message delivery, typing indicators, online status, and delivery/read receipts.
- **Push Notifications**: Integrated Expo Push Notification Service dispatch for offline recipients.
- **Persistent Vault**: Encrypted message queue and vault backed by SQLite with WAL mode.
- **Health Check**: Built-in `/api/health` endpoint for Render keep-alive pingers (UptimeRobot, Cron-Job.org).

---

## 1-Click Deployment to Render

1. Create a new **Web Service** on [Render.com](https://render.com).
2. Connect your GitHub repository `PriyuK/NosePies-server`.
3. Set the following settings:
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `node index.js`
4. Add a **Persistent Disk**:
   - **Name**: `nosepies-data`
   - **Mount Path**: `/app/data`
   - **Size**: 1 GB
5. Set Environment Variable:
   - `DATABASE_PATH`: `/app/data/chat.db`
   - `NODE_ENV`: `production`

---

## Docker Deployment

```bash
# Build Docker image
docker build -t nosepies-server .

# Run with persistent volume
docker run -d -p 4000:4000 -v nosepies_data:/app/data --name nosepies-backend nosepies-server
```

---

## Local Development

```bash
# Install dependencies
npm install

# Start server
npm start
```

Default port: `4000`. Health check: `http://localhost:4000/api/health`.
