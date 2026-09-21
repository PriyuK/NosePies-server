FROM node:20-alpine

# Set working directory
WORKDIR /app

# Install build dependencies for sqlite3 native compilation
RUN apk add --no-cache python3 make g++

# Copy package files and install production dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy application source
COPY . .

# Create directory for persistent SQLite database
RUN mkdir -p /app/data && chown -R node:node /app

# Switch to non-root user
USER node

# Expose default backend port
EXPOSE 4000

# Set environment defaults
ENV PORT=4000
ENV NODE_ENV=production
ENV DATABASE_PATH=/app/data/chat.db

# Run server
CMD ["node", "index.js"]
