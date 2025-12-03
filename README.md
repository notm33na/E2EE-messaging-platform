# Secure E2EE Messaging & File-Sharing System

A complete end-to-end encrypted messaging and file-sharing system with forward secrecy, MITM protection, and comprehensive security features.

## Prerequisites

- **Node.js** (v18 or higher)
- **npm** or **yarn**
- **MongoDB** (optional, for full functionality)
- **mkcert** (for trusted local certificates - see Certificate Setup below)

## Installation

### 1. Install Dependencies

Install dependencies for all packages:

```bash
npm run install:all
```

Or install manually:

```bash
# Root dependencies
npm install

# Server dependencies
cd server
npm install

# Client dependencies
cd ../client
npm install
```

### 2. Environment Setup

Create a `.env` file in the project root (or copy from `env.example` if available):

```env
PORT_HTTP=8080
PORT_HTTPS=8443
MONGO_URI=mongodb://localhost:27017/infosec
NODE_ENV=development
JWT_SECRET=your-secret-key-here
JWT_REFRESH_SECRET=your-refresh-secret-key-here
```

## Certificate Setup (mkcert)

To eliminate browser security warnings, install `mkcert` for trusted local certificates.

### Windows (Chocolatey - Recommended)

1. Install Chocolatey (if not already installed):
   ```powershell
   # Run PowerShell as Administrator
   Set-ExecutionPolicy Bypass -Scope Process -Force
   [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
   iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
   ```

2. Install mkcert:
   ```powershell
   choco install mkcert
   ```

3. Install the local CA:
   ```powershell
   mkcert -install
   ```

### Windows (Scoop)

1. Install Scoop:
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   irm get.scoop.sh | iex
   ```

2. Install mkcert:
   ```powershell
   scoop install mkcert
   ```

3. Install the local CA:
   ```powershell
   mkcert -install
   ```

### Manual Installation

1. Download mkcert from: https://github.com/FiloSottile/mkcert/releases
2. Download `mkcert-v*-windows-amd64.exe` for Windows
3. Rename it to `mkcert.exe` and add it to your PATH
4. Run `mkcert -install` in PowerShell as Administrator

**Note:** The `vite-plugin-mkcert` plugin will automatically generate trusted certificates that include your local IP address.

## Starting the Application

### 1. Start the Backend Server

**Important:** The backend server must be running before the frontend can connect to it.

```bash
# Navigate to server directory
cd server

# Start the server
npm run dev
```

The backend server will start on:
- **HTTP**: `http://localhost:8080` (redirects to HTTPS)
- **HTTPS**: `https://localhost:8443` (main API server)
- **WebSocket**: `wss://localhost:8443` (Socket.IO)

You should see:
```
✓ HTTP server running on port 8080 (redirects to HTTPS)
✓ HTTPS server running on port 8443
✓ API available at: https://localhost:8443/api
✓ WebSocket available at: https://localhost:8443
```

### 2. Start the Frontend Development Server

In a **separate terminal**:

```bash
# Navigate to client directory
cd client

# Start the development server
npm run dev
```

The frontend will start on:
- **Frontend**: `https://localhost:5173` (or `http://localhost:5173`)

The Vite dev server will proxy API requests from `/api` to `https://localhost:8443/api`.

## Development Workflow

1. **Always start backend first**: `cd server && npm run dev`
2. **Then start frontend**: `cd client && npm run dev`
3. **Access the app**: `https://localhost:5173` or `http://localhost:5173`

## Production Build

### Backend
```bash
cd server
npm start
```

### Frontend
```bash
cd client
npm run build
npm run preview
```

## Troubleshooting

### Connection Refused Errors

If you see errors like:
- `ERR_CONNECTION_REFUSED`
- `Network Error: Network Error`
- `Failed to load resource: net::ERR_CONNECTION_REFUSED`

**Solution**: Make sure the backend server is running first!

1. Check if backend is running:
   ```bash
   # In server directory
   npm run dev
   ```

2. Verify backend is accessible:
   - Open `https://localhost:8443/api/health` in your browser
   - You may need to accept the self-signed certificate warning

### Certificate Security Warnings

If you see certificate warnings:

1. **Verify mkcert CA is installed:**
   ```powershell
   mkcert -CAROOT
   ```
   This should show a path. If it doesn't, run `mkcert -install` again.

2. **Clear Vite cache and restart:**
   ```powershell
   cd client
   Remove-Item -Recurse -Force .vite
   Remove-Item -Recurse -Force node_modules\.vite
   npm run dev
   ```

3. **Clear browser cache:**
   - Chrome/Edge: `chrome://settings/clearBrowserData`
   - Firefox: `about:preferences#privacy`

### Vite HMR WebSocket Errors

If you see:
- `WebSocket connection to 'ws://localhost:5173/?token=...' failed`
- `[vite] failed to connect to websocket`

**Solution**: This is usually harmless - it's just Hot Module Replacement (HMR) for live reloading. The app will still work, but you won't get automatic page refreshes on code changes.

To fix:
1. Make sure port 5173 is not blocked by firewall
2. Try restarting the Vite dev server
3. Check if another process is using port 5173

### Port Already in Use

If you get "port already in use" errors:
- **Backend (8443)**: Kill the process using that port or change `PORT_HTTPS` in `.env`
- **Frontend (5173)**: Kill the process or change port in `vite.config.js`

### MongoDB Connection Issues

If MongoDB is not running:
- The server will still start but show a warning
- Some features requiring database will not work
- To use full functionality, start MongoDB: `mongod`

### CORS Errors

CORS is configured on the backend. If you see CORS errors:
- Make sure you're accessing the frontend through `http://localhost:5173` or `https://localhost:5173`
- Don't access the backend directly from the browser (use the proxy)

## Project Structure

```
/
├── client/          → Vite React frontend
├── server/          → Node.js + Express backend
├── keys/            → ECC keys and HTTPS certificates
├── docs/            → Documentation
└── .env             → Environment variables
```

## Tech Stack

- **Frontend**: React (Vite), TailwindCSS
- **Backend**: Node.js + Express
- **Database**: MongoDB
- **Real-time**: WebSockets (Socket.IO)
- **Security**: HTTPS-first, ECC (Elliptic Curve) keypair, JWT
- **Architecture**: Monorepo

## Key Features

- ✅ End-to-end encryption (AES-256-GCM)
- ✅ Forward secrecy via key rotation
- ✅ MITM protection via digital signatures
- ✅ Replay attack prevention
- ✅ Encrypted file sharing (chunked)
- ✅ Comprehensive logging and audit trails
- ✅ Attack simulation and demonstration tools

## Available Scripts

### Root Level
- `npm run install:all` - Install all dependencies
- `npm run dev:server` - Start backend server
- `npm run dev:client` - Start frontend server
- `npm run build` - Build frontend for production
- `npm start` - Start production server

### Client
- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run test:e2e` - Run end-to-end tests
- `npm run test:attacks` - Run attack simulation tests

### Server
- `npm run dev` - Start development server with watch mode
- `npm start` - Start production server
- `npm test` - Run tests
- `npm run test:coverage` - Run tests with coverage
