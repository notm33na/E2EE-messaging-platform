# Deployment Guide

## Local Development

### Prerequisites

- Node.js 18+ installed
- MongoDB Atlas account (free tier works)
- Git installed

### Setup Steps

1. **Clone Repository**:
   ```bash
   git clone <repository-url>
   cd infosec
   ```

2. **Install Dependencies**:
   ```bash
   npm run install:all
   ```

3. **Configure Environment**:
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env`:
   ```env
   MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/dbname
   PORT_HTTP=8080
   PORT_HTTPS=8443
   NODE_ENV=development
   # AI Engine removed - not required for E2EE cryptography system
   ```

4. **Generate ECC Keys**:
   ```bash
   cd server
   npm run generate-keys
   ```

5. **Start Server**:
   ```bash
   npm run dev:server
   ```

6. **Start Client** (new terminal):
   ```bash
   npm run dev:client
   ```

7. **Access Application**:
   - Open browser: `https://localhost:5173`
   - Accept self-signed certificate warning

## Cloud Deployment

### Option 1: Render

1. **Create Render Account**: https://render.com

2. **Create Web Service**:
   - Connect GitHub repository
   - Build command: `cd server && npm install`
   - Start command: `cd server && npm start`
   - Environment: Node
   - Add environment variables from `.env`

3. **Create Static Site** (for client):
   - Connect GitHub repository
   - Build command: `cd client && npm install && npm run build`
   - Publish directory: `client/dist`
   - Add environment variable: `VITE_API_URL=https://your-server.onrender.com`

4. **Configure MongoDB Atlas**:
   - Whitelist Render IP addresses
   - Update `MONGO_URI` in Render environment

### Option 2: Railway

1. **Create Railway Account**: https://railway.app

2. **Deploy Server**:
   - New Project → Deploy from GitHub
   - Select repository
   - Add environment variables
   - Railway auto-detects Node.js

3. **Deploy Client**:
   - New Service → Static Site
   - Connect GitHub repository
   - Build command: `cd client && npm install && npm run build`
   - Output directory: `client/dist`

4. **Configure MongoDB Atlas**:
   - Whitelist Railway IPs
   - Update `MONGO_URI`

### Option 3: VPS (DigitalOcean, AWS, etc.)

1. **Provision VPS**:
   - Ubuntu 22.04 LTS
   - Minimum: 1GB RAM, 1 CPU

2. **Install Dependencies**:
   ```bash
   sudo apt update
   sudo apt install nodejs npm nginx certbot
   ```

3. **Clone Repository**:
   ```bash
   git clone <repository-url>
   cd infosec
   ```

4. **Install Dependencies**:
   ```bash
   npm run install:all
   ```

5. **Configure Environment**:
   ```bash
   cp .env.example .env
   nano .env  # Edit with production values
   ```

6. **Generate ECC Keys**:
   ```bash
   cd server
   npm run generate-keys
   ```

7. **Build Client**:
   ```bash
   cd client
   npm install
   npm run build
   ```

8. **Configure Nginx**:
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;

       location / {
           root /path/to/infosec/client/dist;
           try_files $uri $uri/ /index.html;
       }

       location /api {
           proxy_pass https://localhost:8443;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection 'upgrade';
           proxy_set_header Host $host;
           proxy_cache_bypass $http_upgrade;
       }
   }
   ```

9. **Setup SSL**:
   ```bash
   sudo certbot --nginx -d your-domain.com
   ```

10. **Start Server with PM2**:
    ```bash
    npm install -g pm2
    cd server
    pm2 start src/index.js --name infosec-server
    pm2 save
    pm2 startup
    ```

## Environment Variables

### Server (.env)

```env
# MongoDB
MONGO_URI=mongodb+srv://...

# Server Ports
PORT_HTTP=8080
PORT_HTTPS=8443

# Environment
NODE_ENV=production

# JWT
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d

# AI Engine removed - not required for E2EE cryptography system

# Client URL (for CORS)
CLIENT_URL=https://your-client-domain.com
```

### Client (.env)

```env
VITE_API_URL=https://your-server-domain.com
```

## Security Checklist

- [ ] HTTPS enabled (WSS for WebSockets)
- [ ] CORS configured correctly
- [ ] Environment variables secured
- [ ] MongoDB Atlas IP whitelist configured
- [ ] ECC keys generated and secured
- [ ] No private keys in repository
- [ ] `.env` in `.gitignore`
- [ ] Self-signed certificates replaced with real certificates (production)

## Troubleshooting

### WebSocket Connection Fails

- Check HTTPS/WSS is enabled
- Verify CORS configuration
- Check firewall rules
- Verify certificate validity

### MongoDB Connection Fails

- Verify `MONGO_URI` is correct
- Check IP whitelist in MongoDB Atlas
- Verify network connectivity

### Client Can't Connect to Server

- Check `VITE_API_URL` environment variable
- Verify server is running
- Check CORS headers
- Verify certificate (if self-signed, accept in browser)

## Production Considerations

1. **Use Real SSL Certificates**: Replace self-signed certs with Let's Encrypt or commercial certificates

2. **Rate Limiting**: Implement rate limiting on all endpoints

3. **Monitoring**: Set up logging and monitoring (e.g., Sentry, LogRocket)

4. **Backup**: Regular MongoDB backups

5. **Scaling**: Consider load balancing for high traffic

6. **Security Headers**: Configure security headers (Helmet.js already included)

## Performance Optimization

- Enable gzip compression
- Use CDN for static assets
- Implement caching where appropriate
- Monitor database query performance
- Consider Redis for session storage (future enhancement)

