# Secure E2EE Messaging & File-Sharing System

A complete end-to-end encrypted messaging and file-sharing system with forward secrecy, MITM protection, and comprehensive security features.

## Project Overview

This project implements a secure, end-to-end encrypted (E2EE) messaging and file-sharing system using only Web Crypto API and Node.js crypto modules. No external E2EE libraries are used.

**Key Features**:

- ✅ End-to-end encryption (AES-256-GCM)
- ✅ Forward secrecy via key rotation
- ✅ MITM protection via digital signatures
- ✅ Replay attack prevention
- ✅ Encrypted file sharing (chunked)
- ✅ Comprehensive logging and audit trails
- ✅ Attack simulation and demonstration tools

## Project Structure

```
/
├── client/          → Vite React frontend
├── server/          → Node.js + Express backend
├── keys/            → ECC keys and HTTPS certificates
└── env.example      → Environment variables template
```

## Tech Stack

- **Frontend**: React (Vite)
- **Backend**: Node.js + Express
- **Database**: MongoDB Atlas
- **Real-time**: WebSockets (Socket.IO)
- **Security**: HTTPS-first, ECC (Elliptic Curve) keypair, JWT placeholder
- **Architecture**: Monorepo

## Code Architecture

### Overview

This project follows a **layered architecture** pattern with clear separation of concerns. The codebase is organized into distinct layers for maintainability, testability, and scalability.

```
┌─────────────────────────────────────────────────────────────┐
│                    Client (React Frontend)                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Components  │  │   Services    │  │   WebSocket   │     │
│  │   (UI/UX)    │→ │   (API)      │  │   Client      │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                          │                    │
                    HTTPS/REST API      WebSocket (Socket.IO)
                          │                    │
┌─────────────────────────────────────────────────────────────┐
│              Server (Node.js + Express Backend)              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Routes  │→ │Middleware│→ │  Models  │→ │ Database │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         WebSocket Handler (Socket.IO)                │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                          │
                    MongoDB Atlas
```

### Backend Architecture

The backend follows a **layered architecture** with the following structure:

#### 1. **Entry Point Layer** (`src/index.js`)

- **Responsibility**: Server initialization, HTTP/HTTPS server setup, graceful shutdown
- **Key Functions**:
  - Creates Express app instance
  - Configures HTTP server (redirects to HTTPS)
  - Configures HTTPS server (main application)
  - Initializes WebSocket server
  - Handles process signals for graceful shutdown
  - Orchestrates middleware and route registration

#### 2. **Configuration Layer** (`src/config/`)

- **`database.js`**: MongoDB connection management
  - Establishes connection to MongoDB Atlas
  - Handles connection events (error, disconnect)
  - Provides graceful connection closing
- **`keys.js`**: ECC keypair management
  - Loads private/public keys from filesystem
  - Validates key existence
  - Returns keys in PEM format for JWT signing

#### 3. **Middleware Layer** (`src/middleware/`)

- **`security.js`**: Security middleware configuration
  - **Helmet**: Sets security HTTP headers (CSP, HSTS, etc.)
  - **CORS**: Configures cross-origin resource sharing
  - Environment-aware configuration (dev vs production)

#### 4. **Route Layer** (`src/routes/`)

- **Pattern**: Modular route handlers
- **`health.js`**: Health check endpoint
  - Returns server status, uptime, timestamp
  - Used for monitoring and load balancer health checks

#### 5. **Model Layer** (`src/models/`)

- **Pattern**: Mongoose schemas and models
- **`User.js`**: User model placeholder
  - Defines schema structure
  - Provides data validation
  - Ready for future authentication features

#### 6. **Utility Layer** (`src/utils/`)

- **`https-cert.js`**: HTTPS certificate management
  - Generates self-signed certificates for development
  - Caches certificates to avoid regeneration
  - Uses `selfsigned` library for proper certificate generation
  - Includes Subject Alternative Names (SAN) for localhost

#### 7. **WebSocket Layer** (`src/websocket/`)

- **`socket-handler.js`**: Socket.IO server initialization
  - Creates Socket.IO server instance
  - Handles connection/disconnection events
  - Placeholder event handlers (hello, message echo)
  - CORS configuration for WebSocket connections

#### 8. **Scripts Layer** (`scripts/`)

- **`generate-keys.js`**: ECC keypair generation
  - Uses Node.js crypto module
  - Generates P-256 (prime256v1) curve keys
  - Saves keys with proper file permissions (600 for private, 644 for public)

### Frontend Architecture

The frontend follows a **component-based architecture** with service layer separation:

#### 1. **Entry Point** (`src/main.jsx`)

- React application bootstrap
- Renders root component with React.StrictMode

#### 2. **Component Layer** (`src/components/`)

- **Pattern**: Functional components with hooks
- **`WebSocketTest.jsx`**: WebSocket connection testing component
  - Manages Socket.IO client connection
  - Handles connection state
  - Displays messages and allows sending test messages
  - Demonstrates real-time communication

#### 3. **Service Layer** (`src/services/`)

- **`api.js`**: Axios-based API client
  - **Configuration**: Base URL, timeout, headers
  - **Interceptors**:
    - Request: Adds JWT token from localStorage (future auth)
    - Response: Error handling and logging
  - **Environment-aware**: Uses Vite proxy in development, direct HTTPS in production

#### 4. **Application Layer** (`src/App.jsx`)

- **Main Application Component**
  - Manages application state (connection status, health data)
  - Fetches backend health on mount
  - Displays connection status with visual feedback
  - Conditionally renders WebSocket test component

#### 5. **Configuration** (`vite.config.js`)

- **Vite Configuration**:
  - React plugin for JSX transformation
  - Development server on port 5173
  - Proxy configuration for API calls
  - Handles self-signed certificate issues in development

### Communication Flow

#### HTTP/HTTPS Request Flow

```
Client Component
    ↓
API Service (axios)
    ↓
Vite Proxy (dev) / Direct HTTPS (prod)
    ↓
Express Middleware (CORS, Helmet, Morgan)
    ↓
Route Handler
    ↓
Response
```

#### WebSocket Connection Flow

```
Client Component (Socket.IO Client)
    ↓
WSS Connection (wss://localhost:8443)
    ↓
Socket.IO Server (attached to HTTPS server)
    ↓
Event Handlers
    ↓
Emit Events to Client
```

### Security Architecture

#### HTTPS-First Design

1. **HTTP Server** (port 8080): Only serves 301 redirects to HTTPS
2. **HTTPS Server** (port 8443): Handles all actual traffic
3. **Certificate Management**: Auto-generates self-signed certs in development

#### Security Middleware Stack

```
Request → Helmet (Security Headers) → CORS (Origin Check) → Express (Body Parsing) → Routes
```

#### Key Management

- **ECC Keys**: Stored in `keys/` directory
- **Private Key**: 600 permissions (owner read/write only)
- **Public Key**: 644 permissions (readable by all)
- **HTTPS Certificates**: Auto-generated, cached for performance

### Threat Surface Analysis

This section outlines potential security threats and how the current architecture addresses (or should address) them.

#### ✅ Mitigated Threats

| Threat                                | Mitigation                            | Implementation                                                   |
| ------------------------------------- | ------------------------------------- | ---------------------------------------------------------------- |
| **Man-in-the-Middle (MITM)**          | HTTPS/TLS encryption                  | All traffic forced to HTTPS (port 8443), HTTP redirects to HTTPS |
| **Cross-Site Scripting (XSS)**        | Content Security Policy               | Helmet middleware with CSP headers configured                    |
| **Cross-Site Request Forgery (CSRF)** | SameSite cookies, CORS                | CORS configured for specific origins, future: CSRF tokens        |
| **Information Disclosure**            | Security headers                      | Helmet sets X-Content-Type-Options, X-Frame-Options, etc.        |
| **Clickjacking**                      | X-Frame-Options                       | Helmet prevents iframe embedding                                 |
| **Protocol Downgrade**                | HTTP Strict Transport Security (HSTS) | Helmet HSTS with preload support                                 |
| **Insecure Direct Object References** | Input validation (future)             | Placeholder: needs implementation in route handlers              |
| **Sensitive Data Exposure**           | Key file permissions                  | Private keys stored with 600 permissions (owner-only access)     |

#### ⚠️ Known Vulnerabilities & Risks

| Risk                                  | Severity | Current Status     | Recommendation                                                            |
| ------------------------------------- | -------- | ------------------ | ------------------------------------------------------------------------- |
| **Self-Signed Certificates**          | Medium   | Development only   | Use trusted CA certificates (Let's Encrypt) in production                 |
| **No Authentication**                 | High     | Placeholder JWT    | Implement proper authentication before production                         |
| **No Rate Limiting**                  | Medium   | Not implemented    | Add rate limiting middleware (express-rate-limit)                         |
| **No Input Validation**               | High     | Not implemented    | Add validation middleware (express-validator, Joi)                        |
| **No SQL/NoSQL Injection Protection** | High     | Partial (Mongoose) | Mongoose provides some protection; add input sanitization                 |
| **WebSocket DoS**                     | Medium   | No protection      | Implement connection limits and message size limits                       |
| **Environment Variable Exposure**     | Medium   | .env in .gitignore | Ensure .env never committed; use secrets management in production         |
| **Key Storage**                       | Medium   | Filesystem         | Consider key management service (AWS KMS, HashiCorp Vault) for production |
| **No Request Size Limits**            | Low      | Express default    | Configure body-parser limits explicitly                                   |
| **CORS Too Permissive (Dev)**         | Low      | Development only   | Tighten CORS in production to specific domains                            |
| **No Logging/Monitoring**             | Medium   | Basic (Morgan)     | Add structured logging, error tracking (Sentry), monitoring               |
| **No Session Management**             | High     | Not implemented    | Implement secure session management for authenticated users               |
| **Brute Force Protection**            | Medium   | Not implemented    | Add account lockout and CAPTCHA for login attempts                        |

#### 🔒 Security Best Practices Implemented

1. **HTTPS-First Architecture**: All HTTP traffic redirected to HTTPS
2. **Security Headers**: Helmet middleware sets comprehensive security headers
3. **CORS Configuration**: Restricts cross-origin requests to allowed origins
4. **Key File Permissions**: Private keys protected with restrictive permissions
5. **Environment Variables**: Sensitive data stored in .env (not in code)
6. **ES Modules**: Modern JavaScript reduces some attack vectors
7. **Graceful Shutdown**: Proper cleanup prevents resource leaks

#### 🚨 Critical Security Gaps (Must Address Before Production)

1. **Authentication & Authorization**

   - No user authentication implemented
   - No role-based access control (RBAC)
   - JWT implementation is placeholder only

2. **Input Validation & Sanitization**

   - No request validation middleware
   - No input sanitization
   - Vulnerable to injection attacks

3. **Rate Limiting**

   - No protection against brute force attacks
   - No API rate limiting
   - Vulnerable to DoS attacks

4. **Error Handling**

   - Error messages may leak sensitive information
   - No structured error responses
   - Stack traces exposed in development

5. **Certificate Management**
   - Self-signed certificates not trusted by browsers
   - No certificate rotation mechanism
   - No certificate pinning

#### 📋 Security Checklist for Production

- [ ] Replace self-signed certificates with trusted CA certificates
- [ ] Implement proper authentication (JWT with refresh tokens)
- [ ] Add input validation and sanitization middleware
- [ ] Implement rate limiting (API and authentication endpoints)
- [ ] Add request size limits
- [ ] Implement proper error handling (no stack traces in production)
- [ ] Add security logging and monitoring
- [ ] Configure CORS for production domains only
- [ ] Implement session management
- [ ] Add CSRF protection tokens
- [ ] Use secrets management service (not .env files)
- [ ] Implement database connection pooling limits
- [ ] Add WebSocket connection limits
- [ ] Enable security audit logging
- [ ] Implement security headers validation
- [ ] Add dependency vulnerability scanning
- [ ] Configure firewall rules
- [ ] Implement backup and disaster recovery
- [ ] Add penetration testing
- [ ] Enable security monitoring and alerting

#### 🛡️ Defense in Depth Strategy

The architecture follows a **defense in depth** approach with multiple security layers:

1. **Network Layer**: HTTPS/TLS encryption
2. **Application Layer**: Security middleware (Helmet, CORS)
3. **Data Layer**: Mongoose ODM (partial injection protection)
4. **File System Layer**: Key file permissions
5. **Code Layer**: ES modules, modern JavaScript practices

**Future Layers to Add:**

- Authentication layer (JWT, sessions)
- Authorization layer (RBAC, permissions)
- Validation layer (input sanitization)
- Rate limiting layer
- Monitoring layer (security events, alerts)

### Data Flow

#### Backend Data Flow

```
HTTP Request
    ↓
Express App
    ↓
Security Middleware
    ↓
Route Handler
    ↓
Model Layer (Mongoose)
    ↓
MongoDB Atlas
    ↓
Response
```

#### Frontend Data Flow

```
User Interaction
    ↓
Component State Update
    ↓
API Service Call / WebSocket Event
    ↓
Backend Processing
    ↓
State Update (useState/useEffect)
    ↓
UI Re-render
```

### Module Organization Principles

1. **Separation of Concerns**: Each module has a single, well-defined responsibility
2. **Dependency Injection**: Configuration and utilities are imported where needed
3. **ES Modules**: All code uses ES6 import/export for better tree-shaking
4. **Async/Await**: Consistent asynchronous programming pattern
5. **Error Handling**: Try-catch blocks and graceful error handling throughout
6. **Environment Awareness**: Code adapts to development vs production environments

### File Naming Conventions

- **Files**: kebab-case (e.g., `https-cert.js`, `socket-handler.js`)
- **Classes**: PascalCase (e.g., `User` model)
- **Variables/Functions**: camelCase (e.g., `generateSelfSignedCert`)
- **Components**: PascalCase (e.g., `WebSocketTest.jsx`)

### Extension Points

The architecture is designed for easy extension:

1. **New Routes**: Add files to `src/routes/` and register in `index.js`
2. **New Models**: Add Mongoose schemas to `src/models/`
3. **New Middleware**: Add to `src/middleware/` and register in `index.js`
4. **New Components**: Add React components to `src/components/`
5. **New Services**: Add API services to `src/services/`
6. **WebSocket Events**: Extend handlers in `src/websocket/socket-handler.js`

## Components and Responsibilities

This section provides a detailed breakdown of all components in the codebase, their locations, and their specific responsibilities.

### Backend Components

#### Core Server Files

**`server/src/index.js`**

- **Type**: Main entry point
- **Responsibilities**:
  - Initializes Express application
  - Creates HTTP server (port 8080) for HTTPS redirects
  - Creates HTTPS server (port 8443) with SSL/TLS certificates
  - Loads and applies middleware (security, logging, body parsing)
  - Registers API routes
  - Initializes WebSocket server (Socket.IO)
  - Connects to MongoDB Atlas
  - Handles graceful shutdown (SIGTERM, SIGINT)
  - Manages server lifecycle and error handling

#### Configuration Layer

**`server/src/config/database.js`**

- **Type**: Database configuration module
- **Responsibilities**:
  - Establishes MongoDB Atlas connection using Mongoose
  - Configures connection options (timeout, retry logic)
  - Handles connection events (connect, error, disconnect)
  - Provides `connectDatabase()` function for connection initialization
  - Provides `closeDatabase()` function for graceful disconnection
  - Manages connection state and error recovery

**`server/src/config/keys.js`**

- **Type**: Cryptographic key management module
- **Responsibilities**:
  - Loads ECC private and public keys from filesystem
  - Validates key file existence before loading
  - Returns keys in PEM format for JWT signing
  - Provides secure key access with error handling
  - Used by authentication system (future implementation)

#### Middleware Layer

**`server/src/middleware/security.js`**

- **Type**: Security middleware configuration
- **Responsibilities**:
  - Configures Helmet.js for HTTP security headers
  - Sets Content Security Policy (CSP) directives
  - Configures HTTP Strict Transport Security (HSTS)
  - Sets up CORS with environment-aware origin whitelist
  - Configures allowed HTTP methods and headers
  - Applies security best practices to Express app instance

#### Route Handlers

**`server/src/routes/health.js`**

- **Type**: API route handler
- **Responsibilities**:
  - Implements GET `/api/health` endpoint
  - Returns server status, uptime, and timestamp
  - Provides health check for monitoring and load balancers
  - Handles errors gracefully
  - Returns JSON response with server metrics

#### Data Models

**`server/src/models/User.js`**

- **Type**: Mongoose schema/model
- **Responsibilities**:
  - Defines User data schema (email, createdAt)
  - Enforces data validation rules (required fields, unique email)
  - Provides Mongoose model for database operations
  - Placeholder for future authentication features
  - Includes automatic timestamps (createdAt, updatedAt)

#### Utility Modules

**`server/src/utils/https-cert.js`**

- **Type**: Certificate management utility
- **Responsibilities**:
  - Generates self-signed SSL/TLS certificates for HTTPS
  - Caches certificates to avoid regeneration on each startup
  - Creates certificates with Subject Alternative Names (SAN)
  - Includes localhost and 127.0.0.1 in certificate
  - Saves certificates with proper file permissions
  - Returns certificate and key for HTTPS server configuration
  - Provides development-friendly certificate generation

#### WebSocket Layer

**`server/src/websocket/socket-handler.js`**

- **Type**: WebSocket server initialization
- **Responsibilities**:
  - Initializes Socket.IO server instance
  - Attaches Socket.IO to HTTPS server
  - Configures CORS for WebSocket connections
  - Handles client connection events
  - Handles client disconnection events
  - Implements placeholder event handlers:
    - `hello`: Sends welcome message on connection
    - `message`: Echoes client messages back
  - Logs connection/disconnection events
  - Provides foundation for future real-time features

#### Scripts

**`server/scripts/generate-keys.js`**

- **Type**: Standalone key generation script
- **Responsibilities**:
  - Generates ECC keypair using Node.js crypto module
  - Uses P-256 (prime256v1) curve for ES256 algorithm
  - Creates private and public keys in PEM format
  - Saves keys to `keys/` directory with proper permissions:
    - Private key: 600 (owner read/write only)
    - Public key: 644 (readable by all)
  - Validates keys directory existence
  - Provides console feedback on key generation

#### Configuration Files

**`server/package.json`**

- **Type**: Node.js package configuration
- **Responsibilities**:
  - Defines project metadata and dependencies
  - Lists all npm dependencies (express, mongoose, socket.io, etc.)
  - Defines npm scripts (start, dev, generate-keys)
  - Configures ES modules (type: "module")
  - Manages project version and metadata

### Frontend Components

#### Entry Point

**`client/src/main.jsx`**

- **Type**: React application entry point
- **Responsibilities**:
  - Bootstraps React application
  - Renders root App component
  - Configures React.StrictMode for development warnings
  - Mounts application to DOM element (#root)
  - Initializes React rendering pipeline

#### Main Application Component

**`client/src/App.jsx`**

- **Type**: Main React component
- **Responsibilities**:
  - Manages application-level state (connection status, health data)
  - Fetches backend health status on component mount
  - Displays connection status with visual feedback
  - Handles API errors and displays error messages
  - Conditionally renders WebSocket test component
  - Provides user interface for backend connectivity
  - Manages loading, success, and error states

**`client/src/App.css`**

- **Type**: Application stylesheet
- **Responsibilities**:
  - Defines main application styling
  - Provides gradient background and glassmorphism effects
  - Styles connection status indicators
  - Defines health info display layout
  - Includes loading spinner animations
  - Responsive design considerations

#### Service Layer

**`client/src/services/api.js`**

- **Type**: API client service
- **Responsibilities**:
  - Creates and configures Axios instance
  - Sets base URL (uses Vite proxy in dev, direct HTTPS in prod)
  - Configures request timeout and headers
  - Implements request interceptor for JWT token injection
  - Implements response interceptor for error handling
  - Handles self-signed certificate issues via proxy
  - Provides centralized API configuration
  - Logs API errors for debugging

#### UI Components

**`client/src/components/WebSocketTest.jsx`**

- **Type**: React functional component
- **Responsibilities**:
  - Manages WebSocket connection state
  - Initializes Socket.IO client connection
  - Handles connection/disconnection events
  - Displays WebSocket connection status
  - Manages message history state
  - Provides UI for sending test messages
  - Handles WebSocket errors and displays feedback
  - Demonstrates real-time communication capabilities

**`client/src/components/WebSocketTest.css`**

- **Type**: Component-specific stylesheet
- **Responsibilities**:
  - Styles WebSocket test component
  - Defines message container layout
  - Styles connection status indicators
  - Provides message input and button styling
  - Defines message type visual differentiation

#### Styling

**`client/src/index.css`**

- **Type**: Global stylesheet
- **Responsibilities**:
  - Defines global CSS reset and base styles
  - Sets up font family and typography
  - Configures color scheme (light/dark)
  - Defines root element styling
  - Provides base layout styles

#### Configuration Files

**`client/vite.config.js`**

- **Type**: Vite build tool configuration
- **Responsibilities**:
  - Configures Vite development server (port 5173)
  - Sets up React plugin for JSX transformation
  - Configures proxy for API requests in development
  - Handles self-signed certificate issues via proxy
  - Defines build and preview settings

**`client/package.json`**

- **Type**: Node.js package configuration
- **Responsibilities**:
  - Defines frontend dependencies (React, axios, socket.io-client)
  - Lists development dependencies (Vite, React plugins)
  - Defines npm scripts (dev, build, preview)
  - Configures ES modules
  - Manages frontend project metadata

**`client/index.html`**

- **Type**: HTML entry point
- **Responsibilities**:
  - Defines HTML document structure
  - Sets page title and meta tags
  - Provides root div for React mounting
  - Links to main.jsx entry point
  - Configures viewport for responsive design

### Root-Level Components

**`package.json`** (root)

- **Type**: Monorepo package configuration
- **Responsibilities**:
  - Defines workspace-level npm scripts
  - Provides convenience scripts for running both client and server
  - Manages monorepo metadata
  - Enables unified command execution

**`.env.example`**

- **Type**: Environment variables template
- **Responsibilities**:
  - Documents required environment variables
  - Provides example values for configuration
  - Serves as template for `.env` file creation
  - Documents configuration options

**`README.md`**

- **Type**: Project documentation
- **Responsibilities**:
  - Provides project overview and setup instructions
  - Documents architecture and design decisions
  - Explains security considerations
  - Lists components and their responsibilities
  - Provides troubleshooting guidance

**`.gitignore`**

- **Type**: Git ignore configuration
- **Responsibilities**:
  - Excludes sensitive files from version control
  - Prevents committing node_modules, .env, keys
  - Protects against accidental credential exposure
  - Maintains repository cleanliness

### Component Interaction Flow

```
User Action
    ↓
App.jsx (State Management)
    ↓
api.js (Service Layer)
    ↓
Vite Proxy / Direct HTTPS
    ↓
server/src/index.js (Request Handler)
    ↓
middleware/security.js (Security Layer)
    ↓
routes/health.js (Route Handler)
    ↓
models/User.js (Data Access)
    ↓
config/database.js (Database Connection)
    ↓
MongoDB Atlas
```

### Component Dependencies

**Backend Dependencies:**

- `index.js` → depends on all other backend modules
- `routes/*` → depend on `models/*` for data access
- `models/*` → depend on `config/database.js` for connection
- `websocket/*` → depends on HTTPS server from `index.js`
- `utils/*` → independent utility modules

**Frontend Dependencies:**

- `App.jsx` → depends on `services/api.js` and `components/*`
- `components/*` → depend on `services/api.js` for API calls
- `services/api.js` → independent service layer
- All components → depend on React and React DOM

## Prerequisites

- Node.js (v18 or higher)
- npm or yarn
- MongoDB Atlas account (or local MongoDB)

## Setup Instructions

### 1. Environment Configuration

Copy the environment example file and configure your variables:

```bash
# From project root
cp env.example .env
```

Edit `.env` and add your MongoDB Atlas connection string:

```env
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/dbname?retryWrites=true&w=majority
PORT_HTTP=8080
PORT_HTTPS=8443
NODE_ENV=development

# Token Expiry (optional, defaults: 15m for access, 7d for refresh)
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d

# AI Engine removed - not required for E2EE cryptography system
```

### 2. Generate ECC Keys

Generate the Elliptic Curve keypair for JWT signing:

```bash
cd server
npm install
npm run generate-keys
```

This will create:

- `keys/private_key.pem` - Private key (keep secure!)
- `keys/public_key.pem` - Public key

### 3. Backend Setup

```bash
cd server
npm install
```

The backend will automatically generate a self-signed HTTPS certificate on first run (stored in `keys/server.crt` and `keys/server.key`).

### 4. Frontend Setup

```bash
cd client
npm install
```

## Running the Application

### Start Backend Server

```bash
cd server
npm start
```

Or for development with auto-reload:

```bash
npm run dev
```

The server will start:

- **HTTP** on port `8080` (redirects to HTTPS)
- **HTTPS** on port `8443` (main API)

You should see:

```
✓ HTTP server running on port 8080 (redirects to HTTPS)
✓ HTTPS server running on port 8443
✓ API available at: https://localhost:8443/api
✓ WebSocket available at: https://localhost:8443
```

### Start Frontend

In a new terminal:

```bash
cd client
npm run dev
```

The frontend will start on `http://localhost:5173`

## Testing

### 1. Test Backend Health Endpoint

Open your browser and navigate to:

```
https://localhost:8443/api/health
```

**Note**: You'll see a security warning because we're using a self-signed certificate. This is expected in development. Click "Advanced" → "Proceed to localhost" (or similar).

You should see:

```json
{
  "status": "ok",
  "message": "Server is running",
  "timestamp": "2025-11-30T...",
  "uptime": 123.45
}
```

### 2. Test Frontend Connection

1. Open `http://localhost:5173` in your browser
2. The app will automatically call the backend `/api/health` endpoint
3. You should see "Connected to secure backend" with server information

### 3. Test WebSocket Connection

1. Once the frontend is connected, scroll down to see the WebSocket test component
2. You should see "✓ Connected" status
3. Try sending a message - it will echo back from the server

### 4. Test MongoDB Connection

The backend will automatically connect to MongoDB Atlas on startup if `MONGO_URI` is set in `.env`. Check the console for:

```
✓ Connected to MongoDB Atlas
```

## API Endpoints

### Health Check

- **GET** `/api/health`
- Returns server status and uptime

### Authentication Endpoints

#### Register

- **POST** `/api/auth/register`
- **Body**: `{ email: string, password: string }`
- **Response**: `{ success: true, data: { user, accessToken } }`
- **Cookies**: Sets `refreshToken` (HttpOnly, Secure, SameSite=Strict)
- **Rate Limited**: 5 requests per 15 minutes
- **Password Requirements**:
  - Minimum 8 characters
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one number
  - At least one special character

#### Login

- **POST** `/api/auth/login`
- **Body**: `{ email: string, password: string }`
- **Response**: `{ success: true, data: { user, accessToken } }`
- **Cookies**: Sets `refreshToken` (HttpOnly, Secure, SameSite=Strict)
- **Rate Limited**: 5 requests per 15 minutes

#### Logout

- **POST** `/api/auth/logout`
- **Headers**: `Authorization: Bearer <accessToken>`
- **Response**: `{ success: true, message: "Logout successful" }`
- **Cookies**: Clears `refreshToken`
- **Requires**: Authentication

#### Refresh Token

- **POST** `/api/auth/refresh`
- **Cookies**: Requires `refreshToken` cookie
- **Response**: `{ success: true, data: { accessToken } }`
- **Cookies**: Sets new `refreshToken` (token rotation)
- **Security**: Implements token rotation - old token is revoked, new one issued

#### Get Current User

- **GET** `/api/auth/me`
- **Headers**: `Authorization: Bearer <accessToken>`
- **Response**: `{ success: true, data: { user } }`
- **Requires**: Authentication

#### Deactivate Account

- **POST** `/api/auth/deactivate`
- **Headers**: `Authorization: Bearer <accessToken>`
- **Response**: `{ success: true, message: "Account deactivated successfully" }`
- **Requires**: Authentication
- **Note**: Revokes all refresh tokens and deactivates account

## Authentication System (Phase 2)

### Overview

The application implements a complete JWT-based authentication system using ECC (Elliptic Curve Cryptography) ES256 algorithm for token signing and verification.

### Token Architecture

#### Access Tokens

- **Type**: Short-lived JWT tokens
- **Algorithm**: ES256 (ECC P-256)
- **Default Expiry**: 15 minutes (configurable via `ACCESS_TOKEN_EXPIRY`)
- **Storage**: In-memory only (not localStorage)
- **Usage**: Included in `Authorization: Bearer <token>` header
- **Purpose**: Authenticate API requests

#### Refresh Tokens

- **Type**: Long-lived JWT tokens
- **Algorithm**: ES256 (ECC P-256)
- **Default Expiry**: 7 days (configurable via `REFRESH_TOKEN_EXPIRY`)
- **Storage**: HttpOnly cookie (not accessible via JavaScript)
- **Cookie Settings**:
  - `httpOnly: true` - Prevents XSS attacks
  - `secure: true` - HTTPS only (production)
  - `sameSite: 'strict'` - CSRF protection
- **Purpose**: Obtain new access tokens without re-authentication

### Token Rotation Strategy

The system implements **token rotation** for enhanced security:

1. **On Refresh**: When `/api/auth/refresh` is called:

   - Old refresh token is immediately revoked from database
   - New refresh token is generated and stored
   - New access token is issued
   - Old token cannot be reused

2. **Reuse Detection**: If a refresh token is used after being revoked:

   - System detects token reuse (possible attack)
   - All tokens for that user are immediately revoked
   - User must re-authenticate

3. **Benefits**:
   - Limits damage from token theft
   - Detects compromised tokens
   - Forces re-authentication if token is stolen

### Authentication Flow

#### Registration Flow

```
1. User submits email + password
2. Server validates input (email format, password strength)
3. Password is hashed with bcrypt (10 rounds)
4. User record created in MongoDB
5. Access token + refresh token generated
6. Refresh token stored in database + HttpOnly cookie
7. Access token returned to client
8. Client stores access token in memory
```

#### Login Flow

```
1. User submits email + password
2. Server finds user by email
3. Password verified against stored hash
4. Account status checked (isActive)
5. Last login timestamp updated
6. Access token + refresh token generated
7. Refresh token stored in database + HttpOnly cookie
8. Access token returned to client
9. Client stores access token in memory
```

#### Token Refresh Flow

```
1. Client makes API request with expired access token
2. Server returns 401 Unauthorized
3. Axios interceptor catches 401
4. Client calls /api/auth/refresh (with refresh token cookie)
5. Server verifies refresh token (JWT + database check)
6. Old refresh token revoked from database
7. New refresh token generated and stored
8. New access token generated
9. New tokens returned to client
10. Original API request retried with new access token
```

#### Logout Flow

```
1. Client calls /api/auth/logout with access token
2. Server revokes refresh token from database
3. Refresh token cookie cleared
4. Client clears in-memory access token
5. User redirected to login
```

### WebSocket Authentication

WebSocket connections support JWT authentication:

1. **Connection**: Client connects with JWT token in `auth.token` or query parameter
2. **Verification**: Server verifies token using ECC public key
3. **Identity**: User identity attached to `socket.data.user`
4. **Events**:
   - `auth:hello` - Client can request identity verification
   - Server responds with user info if authenticated
5. **Unauthenticated**: Connections allowed but marked as unauthenticated
6. **Protected Events**: Some events require authentication

### Password Security

- **Hashing**: bcrypt with 10 salt rounds
- **Validation**: Server-side validation with express-validator
- **Requirements**:
  - Minimum 8 characters
  - Uppercase, lowercase, number, special character
- **Storage**: Only password hash stored (never plain text)

### Security Features

1. **ECC ES256 Only**: System rejects HS256 tokens (only accepts ES256)
2. **Token Rotation**: Refresh tokens rotated on every use
3. **Reuse Detection**: Stolen token reuse triggers security response
4. **HttpOnly Cookies**: Refresh tokens not accessible to JavaScript
5. **Secure Cookies**: HTTPS-only in production
6. **SameSite Strict**: CSRF protection
7. **Rate Limiting**: Login/register endpoints rate limited
8. **Input Validation**: All inputs validated and sanitized
9. **Password Strength**: Enforced password requirements
10. **Account Status**: Inactive accounts cannot authenticate

### Testing Authentication

#### Test Registration

```bash
curl -X POST https://localhost:8443/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test123!@#"}'
```

#### Test Login

```bash
curl -X POST https://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test123!@#"}'
```

#### Test Protected Endpoint

```bash
curl -X GET https://localhost:8443/api/auth/me \
  -H "Authorization: Bearer <accessToken>"
```

#### Test Token Refresh

```bash
curl -X POST https://localhost:8443/api/auth/refresh \
  -H "Cookie: refreshToken=<refreshToken>"
```

#### Test WebSocket Authentication

1. Open browser console on dashboard
2. WebSocket automatically connects with JWT token
3. Click "Test Auth" button in WebSocket component
4. Should see authenticated user info

### Environment Variables

Add these to your `.env` file:

```env
# Token Expiry (optional, defaults shown)
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d

# Other existing variables
MONGO_URI=...
PORT_HTTP=8080
PORT_HTTPS=8443
NODE_ENV=development
```

## WebSocket Events

### Client → Server

- `message` - Send a message to the server (requires authentication)
- `auth:hello` - Request identity verification

### Server → Client

- `hello` - Welcome message on connection (includes auth status)
- `message` - Echo of client messages (includes sender email if authenticated)
- `auth:hello` - Identity verification response
- `error` - Error messages (e.g., authentication required)

### WebSocket Authentication

WebSocket connections can be authenticated by providing a JWT token:

**Client-side (Socket.IO):**

```javascript
const socket = io("https://localhost:8443", {
  auth: {
    token: accessToken, // JWT access token
  },
});
```

**Server-side:**

- Token verified using ECC public key
- User identity attached to `socket.data.user`
- Unauthenticated connections allowed but marked
- Protected events require authentication

## Security Features

### HTTPS-First Architecture

- All HTTP traffic (port 8080) automatically redirects to HTTPS (port 8443)
- Self-signed certificates for development (use trusted CA in production)

### Security Middleware

- **Helmet**: Sets secure HTTP headers
- **CORS**: Configured for frontend origin
- **Morgan**: HTTP request logging

### ECC Keypair

- Elliptic Curve Cryptography (P-256, ES256)
- Used for JWT signing and verification
- Private key signs tokens (access & refresh)
- Public key verifies tokens
- Keys stored in `keys/` directory with proper permissions

## Development Notes

### Self-Signed Certificates

The server automatically generates self-signed certificates for HTTPS. In production:

- Use certificates from a trusted CA (e.g., Let's Encrypt)
- Update the certificate loading in `server/src/utils/https-cert.js`

### MongoDB Atlas Connection

1. Create a free cluster at [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)
2. Get your connection string
3. Add it to `.env` as `MONGO_URI`

### Browser Security Warnings

When accessing `https://localhost:8443`, browsers will show a security warning for self-signed certificates. This is normal in development. Click through to proceed.

## Project Structure Details

### Backend (`server/`)

```
server/
├── src/
│   ├── config/
│   │   ├── database.js      → MongoDB connection
│   │   └── keys.js          → ECC key loading
│   ├── middleware/
│   │   └── security.js      → Security middleware setup
│   ├── models/
│   │   └── User.js          → User model placeholder
│   ├── routes/
│   │   └── health.js        → Health check endpoint
│   ├── utils/
│   │   └── https-cert.js    → HTTPS certificate generation
│   ├── websocket/
│   │   └── socket-handler.js → WebSocket initialization
│   └── index.js             → Main server file
├── scripts/
│   └── generate-keys.js     → ECC key generation script
└── package.json
```

### Frontend (`client/`)

```
client/
├── src/
│   ├── components/
│   │   ├── WebSocketTest.jsx → WebSocket test component
│   │   └── WebSocketTest.css
│   ├── services/
│   │   └── api.js           → Axios API service
│   ├── App.jsx              → Main app component
│   ├── App.css
│   ├── main.jsx             → Entry point
│   └── index.css
├── vite.config.js
└── package.json
```

## Troubleshooting

### Port Already in Use

If ports 8080 or 8443 are already in use, change them in `.env`:

```env
PORT_HTTP=8081
PORT_HTTPS=8444
```

### MongoDB Connection Failed

- Verify your `MONGO_URI` is correct
- Check that your IP is whitelisted in MongoDB Atlas
- Ensure your MongoDB user has proper permissions

### HTTPS Certificate Errors

- Delete `keys/server.crt` and `keys/server.key` to regenerate
- Restart the server

### Frontend Can't Connect to Backend

- Ensure backend is running on `https://localhost:8443`
- Check browser console for CORS or certificate errors
- Verify Vite proxy configuration in `client/vite.config.js`

## Phase 2 Features (Completed)

- [x] JWT-based authentication with ECC ES256
- [x] User registration and login
- [x] Protected routes and middleware
- [x] Token rotation strategy
- [x] Refresh token in HttpOnly cookies
- [x] WebSocket authentication
- [x] Password hashing with bcrypt
- [x] Input validation and sanitization
- [x] Rate limiting for auth endpoints
- [x] Auto-refresh token on 401 errors

## Phase 3 Features (Completed)

- [x] Identity key generation (ECC P-256)
- [x] Secure key storage (IndexedDB with password encryption)
- [x] Public key directory (server)
- [x] Key Exchange Protocol (KEP) with authenticated ECDH
- [x] Session key derivation (HKDF)
- [x] Replay protection (timestamp, nonce, sequence)
- [x] WebSocket key exchange events

## Phase 4 Features (Completed)

- [x] AES-256-GCM message encryption
- [x] AES-256-GCM file encryption (chunked)
- [x] Secure message envelope format
- [x] WebSocket message delivery
- [x] Replay and integrity checking
- [x] Metadata-only server persistence
- [x] Client-side decryption flows
- [x] Chat UI for encrypted messaging

## Phase 5 Features (Completed)

- [x] AI-assisted threat analysis
- [x] Deterministic threat scoring
- [x] LLM-based classification
- [x] Combined threat assessment
- [x] Safety guidance generation
- [x] Case summarization
- [x] AI review panel UI (placeholder)

## Phase 6 Features (Completed)

- [x] Forward Secrecy implementation
- [x] Ephemeral key rotation
- [x] Key update protocol (KEY_UPDATE messages)
- [x] Session key rotation in sessionManager
- [x] WebSocket key update relay
- [x] useE2EE React hook
- [x] Secure key storage (memory + IndexedDB)
- [x] Key rotation documentation

## Phase 7 Features (Completed)

- [x] MITM attack simulation (educational)
- [x] Replay attack simulation (educational)
- [x] Attack detection logging
- [x] Comprehensive audit trails
- [x] Evidence capture documentation
- [x] Attack simulation documentation

## Phase 8 Features (Completed)

- [x] Full system integration
- [x] End-to-end testing suite
- [x] Deployment configurations
- [x] Performance benchmarks
- [x] Complete documentation
- [x] Demo scripts
- [x] Final security validation

## Forward Secrecy & Key Rotation (Phase 6)

### Overview

Phase 6 implements **forward secrecy** through periodic key rotation. This ensures that even if session keys are compromised in the future, past messages remain secure.

**Key Features:**

- Ephemeral key pairs generated per rotation
- Session keys derived via ECDH + HKDF
- Old keys discarded after rotation
- Signed key update messages
- Automatic key rotation support

### Forward Secrecy Model

**How It Works:**

1. Initial session uses ephemeral keys from Phase 3 KEP
2. Periodically (or on demand), new ephemeral keys are generated
3. New shared secret computed via ECDH
4. New session keys derived via HKDF
5. Old ephemeral keys discarded
6. Old session keys cannot decrypt new messages

**Security Properties:**

- **Forward Secrecy**: Past messages remain secure even if current keys are compromised
- **Key Isolation**: Each rotation creates independent session keys
- **Signed Updates**: Key updates signed with identity keys prevent MITM
- **Replay Protection**: Timestamp and sequence numbers prevent replay attacks

### Key Rotation Protocol

**Initiating Rotation:**

```javascript
import { initiateKeyRotation } from "./crypto/keyRotation";

const { keyUpdateMessage, newEphPrivateKey } = await initiateKeyRotation(
  sessionId,
  userId,
  peerId,
  password
);

// Send via WebSocket
socket.emit("key:update", keyUpdateMessage);
```

**Responding to Rotation:**

```javascript
import { respondToKeyRotation } from "./crypto/keyRotation";

const { keyUpdateMessage: response } = await respondToKeyRotation(
  keyUpdateMessage,
  peerIdentityPubKey,
  sessionId,
  userId,
  peerId,
  password
);

// Send response
socket.emit("key:update", response);
```

### Key Storage

**Client-Side Storage:**

- **Identity Keys**: Encrypted in IndexedDB (password-derived encryption)
- **Ephemeral Keys**: Memory only (discarded after use)
- **Session Keys**: IndexedDB (encrypted) + memory cache
- **Old Keys**: Discarded immediately after rotation

**Server Storage:**

- **Public Identity Keys**: Stored in MongoDB
- **Public Ephemeral Keys**: Transmitted in KEY_UPDATE messages (not stored)
- **Private Keys**: Never stored on server
- **Session Keys**: Never stored on server

### Message Envelope Format

All encrypted messages use the standard envelope:

```json
{
  "type": "MSG" | "FILE_META" | "FILE_CHUNK",
  "sessionId": "string",
  "sender": "userId",
  "receiver": "userId",
  "ciphertext": "base64",
  "iv": "base64 (96 bits)",
  "authTag": "base64 (128 bits)",
  "timestamp": "number",
  "seq": "number",
  "nonce": "base64",
  "meta": {}
}
```

**Key Update Messages:**

```json
{
  "type": "KEY_UPDATE",
  "sessionId": "string",
  "from": "userId",
  "to": "userId",
  "ephPub": "JWK object",
  "signature": "base64",
  "rotationSeq": "number",
  "timestamp": "number",
  "nonce": "base64"
}
```

### useE2EE Hook

React hook for encrypted messaging:

```javascript
import { useE2EE } from "../hooks/useE2EE";

const { messages, files, isConnected, sendMessage, sendFile, rotateKeys } =
  useE2EE(sessionId, peerId);

// Send message
await sendMessage("Hello, encrypted!");

// Rotate keys
await rotateKeys(password);
```

### Security Considerations

**Forward Secrecy:**

- Old session keys cannot decrypt new messages
- Ephemeral keys discarded immediately after rotation
- Each rotation creates cryptographically independent keys

**Key Rotation Security:**

- Signed with identity keys (prevents MITM)
- Timestamp validation (±2 minutes)
- Sequence numbers prevent replay
- Both parties must acknowledge rotation

**Storage Security:**

- Private keys never leave client
- Session keys encrypted in IndexedDB
- Ephemeral keys in memory only
- Old keys securely discarded

### Implementation Details

**Files:**

- `client/src/crypto/keyRotation.js` - Key rotation protocol
- `client/src/crypto/sessionManager.js` - Enhanced with rotation
- `client/src/hooks/useE2EE.js` - React hook
- `server/src/websocket/socket-handler.js` - Key update relay

**WebSocket Events:**

- `key:update` - Send/receive key update messages
- `key:update:sent` - Confirmation of key update sent

**API Endpoints:**

- WebSocket: `key:update` event
- REST fallback: `/api/crypto/key-update` (future)

### Key Generation Process (Identity Keys)

This section describes how identity key pairs are generated, stored, and used in the E2EE messaging system.

#### 1. Identity Key Purpose

Identity keys are **long-term cryptographic key pairs** that serve as the foundation of user authentication and key exchange security in the system.

**Primary Functions:**

- **Authentication**: Identity keys establish user identity in the system
- **Signing Ephemeral Keys**: Identity private keys sign ephemeral public keys during key exchange to prevent MITM attacks
- **Non-repudiation**: Digital signatures provide cryptographic proof of message origin
- **Trust Establishment**: Public identity keys are stored in a trusted directory for peer verification

**Critical Security Property:**

- Identity private keys are **never transmitted to the server**
- Private keys remain exclusively on the client device
- Only public keys are shared with the server and other users

#### 2. Key Type

Identity keys use **Elliptic Curve Cryptography (ECC)** with the following specifications:

**Algorithm Details:**

- **Curve**: P-256 (prime256v1) or P-384
- **Key Type**: ECDSA (Elliptic Curve Digital Signature Algorithm)
- **Key Size**: 256 bits (P-256) or 384 bits (P-384)
- **API**: Web Crypto API (`crypto.subtle.generateKey`)

**Key Properties:**

- **Private Key**:
  - Extractable: `false` (cannot be exported in raw format)
  - Usages: `['sign']` (used only for signing operations)
  - Stored encrypted in IndexedDB
- **Public Key**:
  - Extractable: `true` (can be exported for sharing)
  - Format: JWK (JSON Web Key) for transmission
  - Usages: `['verify']` (used only for signature verification)
  - Stored on server in public key directory

#### 3. Generation Workflow

**On User Registration:**

1. **Browser Generates Key Pair**:

   - User completes registration form (email, password)
   - Client-side JavaScript calls `crypto.subtle.generateKey()` with ECC P-256 parameters
   - Web Crypto API generates cryptographically secure key pair
   - Generation happens entirely in browser, no server involvement

2. **Private Key Storage**:

   - Private key is stored in **IndexedDB** (preferred) or encrypted localStorage
   - Storage is encrypted using a key derived from user's password via PBKDF2
   - Encryption uses AES-GCM with a password-derived key
   - Private key never leaves the client device

3. **Public Key Export**:

   - Public key is exported to JWK (JSON Web Key) format
   - JWK format includes: `kty` (key type), `crv` (curve), `x`, `y` (coordinates)
   - JWK is a standard format for key exchange

4. **Public Key Upload**:
   - Public key (JWK) is sent to server via `POST /api/keys/upload`
   - Upload requires authenticated user (JWT token)
   - Server validates key format and user identity
   - Server stores public key in MongoDB public key directory

**Server Storage (Public Key Directory):**

- **Stored Fields**:
  - `userId`: Unique user identifier
  - `publicIdentityKeyJWK`: Public key in JWK format
  - `createdAt`: Timestamp of key creation
  - `updatedAt`: Timestamp of last update
- **Not Stored**:
  - ❌ Private key (never sent to server)
  - ❌ Plaintext passwords
  - ❌ Session keys
  - ❌ Any decryptable content

#### 4. Secure Client Storage

**Storage Location:**

- **Primary**: IndexedDB (preferred method)
  - Browser-native database API
  - Persistent storage across sessions
  - Supports structured data storage
  - Isolated per origin (domain)
- **Fallback**: Encrypted localStorage
  - Used if IndexedDB unavailable
  - Less secure than IndexedDB
  - Limited storage capacity

**Encryption Layer:**

- **Password-Derived Key**:
  - User's password used as input to PBKDF2
  - PBKDF2 parameters: SHA-256, 100,000+ iterations, random salt
  - Derived key used for AES-GCM encryption
- **Encryption Process**:
  - Private key serialized to ArrayBuffer
  - Encrypted with AES-GCM using password-derived key
  - IV (Initialization Vector) generated randomly per encryption
  - Encrypted blob stored in IndexedDB with user ID as key
- **Security Properties**:
  - Private key never stored in plaintext
  - Encryption key derived from password (user must remember password)
  - Salt prevents rainbow table attacks
  - High iteration count slows brute-force attacks

**Storage Structure:**

```
IndexedDB: InfosecCryptoDB
  └── identityKeys (ObjectStore)
      └── { userId: "user-123", encryptedPrivateKey: <encrypted blob>, ... }
```

#### 5. Retrieval on Login

**Login Process:**

1. **User Authentication**:

   - User enters email and password
   - Client sends credentials to `POST /api/auth/login`
   - Server validates credentials and returns JWT access token
   - Refresh token stored in HttpOnly cookie

2. **Private Key Loading**:

   - Client receives authentication success
   - Client prompts user for password (if not already available)
   - Client derives encryption key from password using PBKDF2
   - Client retrieves encrypted private key from IndexedDB
   - Client decrypts private key using derived key
   - Private key loaded into memory for signing operations

3. **Key Usage**:
   - Loaded private key used for:
     - Signing ephemeral public keys in key exchange protocol
     - Signing key update messages during key rotation
     - All cryptographic signing operations requiring identity
   - Private key remains in memory during active session
   - Private key never transmitted over network

**Security Considerations:**

- Private key decryption requires user password
- If password is forgotten, private key cannot be recovered (by design)
- Private key is cleared from memory on logout
- Multiple failed decryption attempts may trigger account lockout (future enhancement)

**Key Lifecycle:**

- **Generation**: Once per user (during registration)
- **Storage**: Encrypted in IndexedDB (persistent)
- **Loading**: On each login (decrypted with password)
- **Usage**: During active sessions (signing operations)
- **Rotation**: Not currently implemented (future enhancement)
- **Deletion**: On account deletion (encrypted blob removed from IndexedDB)

### Encryption & Decryption Workflow (Text Summary for Diagram)

This section provides a text-based workflow description suitable for converting into a visual diagram.

#### 1. Sender Side (Encryption)

**Step 1: Load Keys**

- Load identity private key from secure local storage (IndexedDB)
- Load peer's identity public key from server (public key directory)
- Verify session exists or establish new session via key exchange protocol

**Step 2: Establish Session Keys**

- If new session: Perform key exchange protocol (KEP)
  - Generate ephemeral key pair (ECDH P-256)
  - Exchange ephemeral public keys with peer
  - Compute shared secret via ECDH
  - Derive session keys via HKDF-SHA256:
    - rootKey = HKDF(sharedSecret, "ROOT", sessionId, 256 bits)
    - sendKey = HKDF(rootKey, "SEND", userId, 256 bits)
    - recvKey = HKDF(rootKey, "RECV", peerId, 256 bits)
- If existing session: Load session keys from IndexedDB

**Step 3: Prepare Message**

- Get plaintext message from user input
- Generate current timestamp (milliseconds since epoch)
- Get next sequence number for session (strictly increasing)
- Generate random nonce (16 bytes) for additional replay protection

**Step 4: Generate Encryption Parameters**

- Generate random 96-bit (12-byte) IV for AES-GCM
- IV must be unique per message
- Use cryptographically secure random number generator

**Step 5: Encrypt Message**

- Import sendKey as AES-GCM key (256 bits)
- Encrypt plaintext using AES-256-GCM:
  - Algorithm: AES-GCM
  - Key: sendKey (256 bits)
  - IV: Random 96-bit IV
  - Tag length: 128 bits
- Result: ciphertext + authentication tag

**Step 6: Build Message Envelope**

- Create envelope structure:
  - type: "MSG" (or "FILE_META"/"FILE_CHUNK" for files)
  - sessionId: Current session identifier
  - sender: User ID
  - receiver: Peer user ID
  - ciphertext: Base64-encoded encrypted data
  - iv: Base64-encoded initialization vector
  - authTag: Base64-encoded authentication tag
  - timestamp: Message timestamp
  - seq: Sequence number
  - nonce: Base64-encoded nonce

**Step 7: Send to Server**

- Transmit envelope via WebSocket (preferred) or REST API
- Server receives envelope and stores only metadata:
  - sessionId, sender, receiver, timestamp, seq, type
  - Server does NOT store ciphertext, iv, authTag, or nonce
  - Server forwards envelope to recipient if online
  - Server queues envelope if recipient offline

#### 2. Receiver Side (Decryption)

**Step 1: Receive Envelope**

- Receive message envelope via WebSocket or REST API
- Envelope contains: ciphertext, iv, authTag, timestamp, seq, metadata

**Step 2: Validate Envelope Structure**

- Verify all required fields are present
- Verify field types and formats (base64 strings, numbers)
- Verify message type is valid ("MSG", "FILE_META", "FILE_CHUNK")
- Reject if structure invalid

**Step 3: Validate Timestamp Freshness**

- Calculate message age: `currentTime - messageTimestamp`
- Verify timestamp is within validity window: `|age| <= 2 minutes`
- Reject if timestamp is stale (older than 2 minutes)
- Reject if timestamp is from future (more than 2 minutes ahead)
- Log replay attempt if timestamp invalid

**Step 4: Validate Sequence Number**

- Load last sequence number for session from IndexedDB
- Verify new sequence number is strictly greater than last sequence
- Reject if sequence number is not monotonic (replay attempt)
- Log replay attempt if sequence invalid

**Step 5: Load Session Keys**

- Load session from IndexedDB using sessionId
- Extract recvKey (receive key) from session
- Verify session exists and keys are available
- Reject if session not found

**Step 6: Decode Base64 Fields**

- Decode ciphertext from base64 to ArrayBuffer
- Decode IV from base64 to Uint8Array (12 bytes)
- Decode authTag from base64 to ArrayBuffer (16 bytes)
- Verify decoded lengths are correct

**Step 7: Decrypt Message**

- Import recvKey as AES-GCM key (256 bits)
- Combine ciphertext and authTag into single buffer
- Decrypt using AES-256-GCM:
  - Algorithm: AES-GCM
  - Key: recvKey (256 bits)
  - IV: Decoded IV (96 bits)
  - Tag: Decoded authTag (128 bits)
- If auth tag is invalid, decryption throws OperationError
- If decryption succeeds, plaintext is recovered

**Step 8: Verify Integrity**

- AES-GCM automatically verifies authentication tag during decryption
- If tag is invalid, decryption fails (prevents tampering)
- If tag is valid, message integrity is confirmed
- Log invalid signature/tampering attempt if decryption fails

**Step 9: Update Session State**

- Update last sequence number in session to current message seq
- Update last timestamp in session to current message timestamp
- Persist updated session to IndexedDB
- This prevents accepting the same message twice

**Step 10: Display Plaintext**

- Plaintext message is now available in client memory only
- Display decrypted message to user in chat interface
- Plaintext never stored on disk or sent to server
- Plaintext exists only in browser RAM

#### Key Points for Diagram

**Encryption Flow**:

- Plaintext → Session Key → AES-GCM Encryption → Ciphertext + Auth Tag + IV → Envelope → Server (metadata only)

**Decryption Flow**:

- Envelope → Validation (timestamp, sequence) → Session Key → AES-GCM Decryption → Plaintext (client memory only)

**Security Boundaries**:

- Encryption happens entirely on sender's client
- Decryption happens entirely on receiver's client
- Server only sees encrypted ciphertext and metadata
- Server never sees plaintext or session keys
- Plaintext exists only in client RAM

**Replay Protection**:

- Timestamp validation prevents old message replay
- Sequence number validation prevents duplicate replay
- Message ID uniqueness prevents exact replay
- All validation happens before decryption

## Attack Simulations & Evidence (Phase 7)

### Overview

Phase 7 provides educational attack simulations to demonstrate security vulnerabilities and how our E2EE system prevents them. **All attacks are simulated locally for educational purposes only.**

**⚠️ Important**: These are educational demonstrations, not real attacks. They run only in local development environments.

### MITM Attack Simulation

**Purpose**: Demonstrates that unsigned ECDH is vulnerable to MITM attacks, and how digital signatures prevent them.

**Files**:

- `client/src/attacks/mitmSimulator.js`

**Simulation 1: Unsigned ECDH (Vulnerable)**

```javascript
import { simulateMITMOnUnsignedECDH } from "./attacks/mitmSimulator.js";

// Shows how attacker can intercept and replace ephemeral keys
// Result: Attack successful - attacker can decrypt all messages
const result = await simulateMITMOnUnsignedECDH(
  sessionId,
  aliceEphPub,
  bobEphPub
);
```

**Simulation 2: Signed ECDH (Protected)**

```javascript
import { simulateMITMOnSignedECDH } from "./attacks/mitmSimulator.js";

// Shows how signature verification prevents MITM
// Result: Attack blocked - signature verification fails
const result = await simulateMITMOnSignedECDH(
  sessionId,
  aliceEphPub,
  aliceIdentityPrivKey,
  aliceIdentityPubKey,
  bobEphPub,
  bobIdentityPrivKey,
  bobIdentityPubKey
);
```

**Key Findings**:

- **Without signatures**: Attacker can replace ephemeral keys and decrypt all messages
- **With signatures**: Signature verification detects key modification and blocks attack
- **Protection**: Identity key signatures ensure ephemeral keys are authentic

### Replay Attack Simulation

**Purpose**: Demonstrates how timestamp and sequence number validation prevent replay attacks.

**Files**:

- `client/src/attacks/replaySimulator.js`

**Simulation**:

```javascript
import {
  captureMessage,
  simulateReplayWithTimestampCheck,
  simulateReplayWithSequenceCheck,
} from "./attacks/replaySimulator.js";

// Capture a message
await captureMessage(sessionId, envelope);

// Attempt to replay (should fail)
const result = await simulateReplayWithTimestampCheck(
  sessionId,
  envelope,
  lastSeq
);
```

**Protection Mechanisms**:

1. **Timestamp Freshness**: Messages older than ±2 minutes are rejected
2. **Sequence Monotonicity**: Sequence numbers must be strictly increasing
3. **Message ID Uniqueness**: Database enforces unique message IDs

**Key Findings**:

- Replayed messages are detected and rejected
- Timestamp validation prevents old message replay
- Sequence number validation prevents duplicate message replay

### Logging & Audit Trails

**Server Logs** (in `server/logs/`):

- `replay_attempts.log` - Replay attack attempts
- `invalid_signature.log` - Invalid signature detections
- `key_exchange_attempts.log` - Key exchange events
- `authentication_attempts.log` - Auth success/failure
- `failed_decryption.log` - Failed decryption attempts
- `message_metadata_access.log` - Metadata access events

**Log Format**:

```json
{
  "timestamp": "2025-11-30T21:35:00.000Z",
  "eventType": "REPLAY_ATTEMPT",
  "sessionId": "session-123",
  "userId": "user-456",
  "seq": 5,
  "reason": "Sequence number not monotonic",
  "action": "REJECTED"
}
```

**Security Considerations**:

- Logs never contain plaintext messages
- Logs never contain private keys
- Only metadata and attack indicators are logged
- All logs are timestamped and auditable

### Evidence Capture

**Packet Capture**:

1. Use Wireshark or Burp Suite to capture WebSocket traffic
2. Filter for `wss://localhost:8443` connections
3. Look for:
   - KEP_INIT/KEP_RESPONSE messages
   - KEY_UPDATE messages
   - Encrypted message envelopes
   - Signature verification failures

**HAR File Export**:

1. Use browser DevTools Network tab
2. Record WebSocket traffic
3. Export as HAR file
4. Annotate for demonstration:
   - MITM attempt (signature verification failure)
   - Replay attempt (timestamp/sequence rejection)
   - Successful key exchange

**Demonstration Steps**:

1. **MITM Attack**:

   - Run unsigned ECDH simulation → Attack succeeds
   - Run signed ECDH simulation → Attack blocked
   - Check logs: `invalid_signature.log` shows signature failures

2. **Replay Attack**:

   - Capture a message
   - Attempt to replay → Rejected
   - Check logs: `replay_attempts.log` shows rejection

3. **Evidence**:
   - Export attack logs as JSON
   - Capture network traffic
   - Document findings

### Attack Simulation API

**MITM Simulator**:

```javascript
import {
  simulateMITMOnUnsignedECDH,
  simulateMITMOnSignedECDH,
  getAttackLog,
  exportAttackLog,
} from "./attacks/mitmSimulator.js";
```

**Replay Simulator**:

```javascript
import {
  captureMessage,
  resendMessage,
  simulateReplayWithTimestampCheck,
  getReplayAttackLog,
  exportReplayAttackLog,
} from "./attacks/replaySimulator.js";
```

### Reproducing Attacks Safely

**Prerequisites**:

- Local development environment only
- No production data
- Controlled test environment

**Steps**:

1. Start server and client locally
2. Create test users
3. Establish test session
4. Run attack simulations
5. Review logs and evidence
6. Document findings

**Safety**:

- All attacks are simulated
- No real user data is compromised
- Logs contain only metadata
- Private keys never exposed

## AI Engine (Removed)

**Status**: AI engine has been removed from the project. This E2EE cryptography system does not require AI functionality. All AI-related code, dependencies, and routes have been removed to maintain focus on cryptographic security.

## Next Steps (Future Phases)

- [ ] Add email verification
- [ ] Implement password reset flow
- [ ] Add two-factor authentication (2FA)
- [ ] Admin panel and user management
- [ ] Enhanced audit logging

## 🔐 Cryptographic Protocol Overview (For Diagram Construction)

This section provides detailed specifications for constructing protocol diagrams. It documents all cryptographic components, flows, and interactions without visual diagrams.

### 1. Key Materials and Identities

#### Long-Term Identity Keys (ECC P-256)

- **IK_priv** (Private Identity Key)

  - Generated: On user registration
  - Algorithm: ECDSA, P-256 curve
  - Storage: Encrypted in IndexedDB (AES-GCM with password-derived key)
  - Usage: Signs ephemeral public keys in KEP
  - Location: Client-only, never transmitted

- **IK_pub** (Public Identity Key)
  - Generated: Same time as IK_priv
  - Format: JWK (JSON Web Key)
  - Storage: Server public key directory (MongoDB)
  - Usage: Verifies signatures on ephemeral keys
  - Location: Server + shared with peers

#### Ephemeral Session Keys (ECDH P-256)

- **EK_priv** (Ephemeral Private Key)

  - Generated: Per session, during key exchange
  - Algorithm: ECDH, P-256 curve
  - Storage: Session memory only (not persisted)
  - Usage: Computes shared secret via ECDH
  - Lifetime: Single session

- **EK_pub** (Ephemeral Public Key)
  - Generated: Same time as EK_priv
  - Format: JWK
  - Storage: Transmitted in KEP messages, not stored
  - Usage: Exchanged with peer for shared secret computation
  - Lifetime: Single session

#### Session Secrets (Derived via ECDH)

- **sharedSecret** (ECDH Output)
  - Computation: `ECDH(EK_priv_A, EK_pub_B)` or `ECDH(EK_priv_B, EK_pub_A)`
  - Size: 256 bits (32 bytes)
  - Storage: Temporary, used only for key derivation
  - Note: Both parties compute same value from their perspective

#### Derived Keys (HKDF-SHA256)

- **rootKey**

  - Derivation: `HKDF(sharedSecret, salt="ROOT", info=sessionId, length=256)`
  - Storage: IndexedDB (encrypted as base64)
  - Usage: Base for further key derivation

- **sendKey**

  - Derivation: `HKDF(rootKey, salt="SEND", info=userId, length=256)`
  - Storage: IndexedDB (encrypted as base64)
  - Usage: Encrypts outgoing messages (AES-256-GCM)

- **recvKey**
  - Derivation: `HKDF(rootKey, salt="RECV", info=peerId, length=256)`
  - Storage: IndexedDB (encrypted as base64)
  - Usage: Decrypts incoming messages (AES-256-GCM)

**Key Storage Summary:**

- Identity keys: Client IndexedDB (private encrypted), Server MongoDB (public)
- Ephemeral keys: Client memory only (not stored)
- Session keys: Client IndexedDB (rootKey, sendKey, recvKey)

### 2. High-Level Protocol Flow (Text Description)

#### Step 1 — Identity Key Lookup

- Client A requests Client B's public identity key
- Endpoint: `GET /api/keys/:userId`
- Server returns: `IK_pub_B` (JWK format)
- Client A imports key for signature verification
- **Note**: Server stores only public keys, never private keys

#### Step 2 — Ephemeral Key Generation

- Client A generates: `EK_priv_A`, `EK_pub_A` (ECDH P-256)
- Client B generates: `EK_priv_B`, `EK_pub_B` (ECDH P-256)
- Generated independently by each client
- Stored in memory only (not persisted)

#### Step 3 — Exchange of Ephemeral Keys

**Flow A → B:**

1. Client A creates KEP_INIT message with `EK_pub_A`
2. Client A sends to server via WebSocket: `socket.emit("kep:init", message)`
3. Server validates timestamp, stores metadata
4. Server forwards to Client B: `recipientSocket.emit("kep:init", message)`

**Flow B → A:**

1. Client B creates KEP_RESPONSE message with `EK_pub_B`
2. Client B sends to server via WebSocket: `socket.emit("kep:response", message)`
3. Server validates timestamp, stores metadata
4. Server forwards to Client A: `recipientSocket.emit("kep:response", message)`

**Server Role**: Relays public keys only, cannot decrypt or modify

#### Step 4 — Authenticating Ephemeral Keys With Signatures

**Signed Payload Format:**

- Data signed: `JSON.stringify(EK_pub_JWK)`
- Signature algorithm: ECDSA with SHA-256
- Signing key: `IK_priv` (identity private key)

**Signature Fields in KEP Messages:**

- `ephPub`: Ephemeral public key (JWK)
- `signature`: Base64-encoded signature
- `timestamp`: Message timestamp (milliseconds)
- `nonce`: Random nonce (16 bytes, base64)

**Verification Rules:**

1. Peer imports `IK_pub` from server
2. Verifies signature: `verify(IK_pub, signature, ephPub_JWK_string)`
3. Validates timestamp: `|now - timestamp| <= 2 minutes`
4. Validates nonce uniqueness (client-side tracking)

**Replay Protection:**

- Timestamp window: ±2 minutes
- Nonce: Unique per message
- Sequence numbers: Strictly increasing
- Message ID uniqueness: Database constraint

#### Step 5 — Key Agreement

**ECDH Computations:**

- Client A computes: `sharedSecret = ECDH(EK_priv_A, EK_pub_B)`
- Client B computes: `sharedSecret = ECDH(EK_priv_B, EK_pub_A)`
- Both produce identical 256-bit shared secret

**Note**: Only ephemeral keys used for ECDH (not identity keys). Identity keys are for signing only.

#### Step 6 — Session Key Derivation

**HKDF Inputs:**

- Input key material: `sharedSecret` (from ECDH)
- Salt: Context-specific ("ROOT", "SEND", "RECV")
- Info: Session identifier and user IDs
- Hash: SHA-256
- Length: 256 bits per key

**Derivation Chain:**

```
sharedSecret (ECDH output)
    ↓
rootKey = HKDF(sharedSecret, "ROOT", sessionId, 256)
    ↓
sendKey = HKDF(rootKey, "SEND", userId, 256)
recvKey = HKDF(rootKey, "RECV", peerId, 256)
```

**Directionality Rules:**

- Client A uses `sendKey_A` to encrypt, `recvKey_A` to decrypt
- Client B uses `sendKey_B` to encrypt, `recvKey_B` to decrypt
- `sendKey_A == recvKey_B` (same key, different names)
- `sendKey_B == recvKey_A` (same key, different names)

#### Step 7 — Key Confirmation

**Key Confirmation Message:**

- Included in KEP_RESPONSE
- Format: `HMAC-SHA256(rootKey, "CONFIRM:" + peerUserId)`
- Field: `keyConfirmation` (base64)

**Confirmation Logic:**

1. Responder (B) computes: `HMAC(rootKey, "CONFIRM:" + A_userId)`
2. Responder includes in KEP_RESPONSE
3. Initiator (A) receives KEP_RESPONSE
4. Initiator computes: `HMAC(rootKey, "CONFIRM:" + A_userId)`
5. Initiator compares: computed == received
6. If match: Session established ✓
7. If mismatch: Session rejected, keys discarded

**Failure Handling:**

- Key confirmation failure indicates key derivation mismatch
- Possible causes: MITM attack, implementation error
- Action: Reject session, log security event, require new key exchange

### 3. Message Envelope Structure (For Diagram Reference)

**Complete Envelope JSON:**

```json
{
  "type": "MSG" | "FILE_META" | "FILE_CHUNK",
  "sessionId": "string",
  "sender": "userId (string)",
  "receiver": "userId (string)",
  "ciphertext": "base64 (encrypted content)",
  "iv": "base64 (96-bit IV)",
  "authTag": "base64 (128-bit tag)",
  "timestamp": "number (milliseconds)",
  "seq": "number (sequence)",
  "nonce": "base64 (16 bytes)",
  "meta": {
    // FILE_META: { filename, size, totalChunks, mimetype }
    // FILE_CHUNK: { chunkIndex, totalChunks }
  }
}
```

**Field Transmission:**

- **WebSocket**: All fields transmitted in real-time
- **REST Fallback**: Same envelope structure via `POST /api/messages/relay`
- **Stored Metadata**: Server stores only: `sessionId`, `sender`, `receiver`, `type`, `timestamp`, `seq`, `meta` (no ciphertext, iv, authTag, nonce)

**Field Purposes:**

- `type`: Message type identifier
- `sessionId`: Links to session keys
- `sender/receiver`: Routing information
- `ciphertext`: Encrypted message content (AES-256-GCM)
- `iv`: Initialization vector (unique per message)
- `authTag`: Authentication tag (integrity verification)
- `timestamp`: Replay protection (freshness check)
- `seq`: Sequence number (ordering and replay protection)
- `nonce`: Additional replay protection
- `meta`: Optional metadata (file information)

### Custom Key Exchange Protocol (ECDH + Signatures + HKDF)

This section provides a detailed, step-by-step description of the custom Key Exchange Protocol (KEP) used to establish secure session keys between two parties. The protocol combines ECDH key exchange, digital signatures, and HKDF key derivation to provide authenticated key exchange with forward secrecy.

#### Pre-Conditions

Before the key exchange protocol can begin, the following conditions must be met:

**Identity Keys Established:**

- Both users (Client A and Client B) have long-term identity ECC key pairs generated during registration
- Client A has: `IK_priv_A` (private) and `IK_pub_A` (public)
- Client B has: `IK_priv_B` (private) and `IK_pub_B` (public)
- Identity private keys are stored encrypted on each client's device (IndexedDB)
- Identity private keys are never transmitted to the server

**Public Key Directory:**

- Server maintains a public key directory (MongoDB collection)
- Server stores only public identity keys: `IK_pub_A` and `IK_pub_B` in JWK format
- Server does NOT store private keys, session keys, or any decryptable content
- Clients can retrieve peer's public identity key via `GET /api/keys/:userId`

**Authentication:**

- Both clients are authenticated (have valid JWT access tokens)
- WebSocket connections are authenticated during handshake
- Server verifies JWT tokens before allowing key exchange messages

#### Step 1 — Ephemeral Key Generation

**Client A (Initiator):**

1. **Generate Ephemeral Key Pair**:

   - Client A calls `crypto.subtle.generateKey()` with ECDH P-256 parameters
   - Generates fresh ephemeral key pair: `EK_priv_A` (private) and `EK_pub_A` (public)
   - Ephemeral keys are generated per session (not reused across sessions)
   - Ephemeral private key stored in memory only (not persisted)

2. **Export Ephemeral Public Key**:

   - Export `EK_pub_A` to JWK (JSON Web Key) format
   - JWK includes: `kty: "EC"`, `crv: "P-256"`, `x`, `y` coordinates
   - JWK format is standard and interoperable

3. **Sign Ephemeral Public Key**:

   - Create payload: `JSON.stringify(EK_pub_A_JWK)`
   - Convert payload to ArrayBuffer using TextEncoder
   - Sign payload using `IK_priv_A` (identity private key) with ECDSA SHA-256
   - Signature algorithm: `{ name: "ECDSA", hash: "SHA-256" }`
   - Result: Base64-encoded signature

4. **Generate Replay Protection**:
   - Generate current timestamp (milliseconds since epoch)
   - Generate random nonce (16 bytes, cryptographically random)
   - Nonce provides additional uniqueness for replay protection

**Client B (Responder):**

- Client B performs the same steps when responding:
  - Generates `EK_priv_B` and `EK_pub_B`
  - Signs `EK_pub_B` with `IK_priv_B`
  - Generates timestamp and nonce

**Key Properties:**

- Ephemeral keys are single-use (discarded after session establishment)
- Ephemeral keys provide forward secrecy (compromised keys don't affect past sessions)
- Signatures prevent MITM attacks (attacker cannot forge signatures without identity private key)

#### Step 2 — Exchange via Server

**Client A → Server → Client B (KEP_INIT):**

1. **Client A Creates KEP_INIT Message**:

   ```json
   {
     "type": "KEP_INIT",
     "from": "aliceId",
     "to": "bobId",
     "sessionId": "session-abc123",
     "ephPub": <EK_pub_A as JWK>,
     "signature": <base64 signature of ephPub>,
     "timestamp": 1234567890,
     "seq": 1,
     "nonce": <base64 nonce>
   }
   ```

2. **Client A Sends to Server**:

   - Sends KEP_INIT via WebSocket: `socket.emit("kep:init", message)`
   - Or via REST API: `POST /api/kep/send` (fallback)
   - Message includes signed ephemeral public key, timestamp, and nonce

3. **Server Receives and Validates**:

   - Server validates message structure (required fields present)
   - Server validates timestamp freshness (±2 minutes window)
   - Server stores message metadata in MongoDB (not the full message)
   - Server does NOT verify signatures (client-side only)
   - Server does NOT decrypt or modify message content

4. **Server Forwards to Client B**:
   - If Client B is online: Server emits `kep:init` event to Client B's WebSocket
   - If Client B is offline: Server stores message as pending for later delivery
   - Server acts as pure relay (no decryption, no modification)

**Client B → Server → Client A (KEP_RESPONSE):**

1. **Client B Creates KEP_RESPONSE Message**:

   ```json
   {
     "type": "KEP_RESPONSE",
     "from": "bobId",
     "to": "aliceId",
     "sessionId": "session-abc123",
     "ephPub": <EK_pub_B as JWK>,
     "signature": <base64 signature of ephPub>,
     "keyConfirmation": <base64 HMAC>,
     "timestamp": 1234567891,
     "seq": 2,
     "nonce": <base64 nonce>
   }
   ```

2. **Client B Sends to Server**:

   - Sends KEP_RESPONSE via WebSocket: `socket.emit("kep:response", message)`
   - Includes signed ephemeral public key and key confirmation HMAC

3. **Server Forwards to Client A**:
   - Server relays message to Client A via WebSocket
   - Server stores metadata only (sender, receiver, sessionId, timestamp, seq)

**Server Role:**

- ✅ Relays messages between clients
- ✅ Validates timestamp freshness (replay protection)
- ✅ Stores message metadata for audit
- ❌ Does NOT verify signatures
- ❌ Does NOT decrypt messages
- ❌ Does NOT modify message content

#### Step 3 — Signature Verification

**Client B Verifies Client A's Signature (KEP_INIT):**

1. **Retrieve Client A's Identity Public Key**:

   - Client B fetches `IK_pub_A` from server: `GET /api/keys/aliceId`
   - Server returns public key in JWK format
   - Client B imports public key: `crypto.subtle.importKey()` with ECDSA parameters

2. **Reconstruct Signed Payload**:

   - Extract `ephPub` from KEP_INIT message
   - Create payload string: `JSON.stringify(ephPub)`
   - Convert to ArrayBuffer: `new TextEncoder().encode(payloadString)`

3. **Verify Signature**:

   - Decode signature from base64 to ArrayBuffer
   - Call `crypto.subtle.verify()` with:
     - Algorithm: `{ name: "ECDSA", hash: "SHA-256" }`
     - Key: `IK_pub_A` (imported public key)
     - Signature: Decoded signature ArrayBuffer
     - Data: Payload ArrayBuffer
   - Returns: `true` if signature valid, `false` if invalid

4. **Validate Timestamp**:

   - Calculate message age: `currentTime - messageTimestamp`
   - Verify: `|age| <= 2 minutes` (120,000 milliseconds)
   - Reject if timestamp is stale (older than 2 minutes)
   - Reject if timestamp is from future (more than 2 minutes ahead)

5. **Check for Replay**:
   - Verify nonce uniqueness (client-side tracking)
   - Verify sequence number is valid (if applicable)
   - Reject if message appears to be a replay

**Rejection Scenarios:**

- ❌ **Invalid Signature**: Signature verification fails → Message rejected, logged to `invalid_signature.log`
- ❌ **Stale Timestamp**: Message age > 2 minutes → Message rejected, logged to `replay_attempts.log`
- ❌ **Future Timestamp**: Message timestamp > currentTime + 2 minutes → Message rejected
- ❌ **Replay Detected**: Nonce or sequence already seen → Message rejected, logged to `replay_attempts.log`

**Client A Verifies Client B's Signature (KEP_RESPONSE):**

- Client A performs the same verification steps using `IK_pub_B`
- Verifies signature, timestamp, and replay protection
- Additionally verifies key confirmation HMAC (see Step 6)

#### Step 4 — Shared Secret Derivation

**Client A Computes Shared Secret:**

1. **Import Client B's Ephemeral Public Key**:

   - Extract `ephPub` from KEP_RESPONSE message (JWK format)
   - Import public key: `crypto.subtle.importKey()` with ECDH P-256 parameters
   - Result: `EK_pub_B` as CryptoKey object

2. **Compute ECDH Shared Secret**:
   - Call `crypto.subtle.deriveBits()` with:
     - Algorithm: `{ name: "ECDH", namedCurve: "P-256", public: EK_pub_B }`
     - Base key: `EK_priv_A` (Client A's ephemeral private key)
     - Length: 256 bits (32 bytes)
   - Result: `sharedSecret` as ArrayBuffer (256 bits)

**Client B Computes Shared Secret:**

1. **Import Client A's Ephemeral Public Key**:

   - Extract `ephPub` from KEP_INIT message (JWK format)
   - Import public key with ECDH P-256 parameters
   - Result: `EK_pub_A` as CryptoKey object

2. **Compute ECDH Shared Secret**:
   - Call `crypto.subtle.deriveBits()` with:
     - Algorithm: `{ name: "ECDH", namedCurve: "P-256", public: EK_pub_A }`
     - Base key: `EK_priv_B` (Client B's ephemeral private key)
     - Length: 256 bits (32 bytes)
   - Result: `sharedSecret` as ArrayBuffer (256 bits)

**Key Property:**

- Both clients compute the **same shared secret** despite using different private keys
- This is the mathematical property of ECDH: `ECDH(EK_priv_A, EK_pub_B) = ECDH(EK_priv_B, EK_pub_A)`
- The shared secret is 256 bits (32 bytes) of cryptographically strong random data

**Security Note:**

- Only ephemeral keys are used for ECDH (not identity keys)
- Identity keys are used only for signing (not for key exchange)
- Ephemeral keys are discarded after shared secret computation

#### Step 5 — HKDF Key Derivation

**HKDF (HMAC-based Key Derivation Function) Overview:**

- HKDF-SHA256 is used to derive multiple session keys from the shared secret
- HKDF provides cryptographically strong key derivation
- Input: shared secret (256 bits)
- Output: multiple derived keys (256 bits each)

**Derivation Chain:**

1. **Derive Root Key**:

   ```
   rootKey = HKDF(
     inputKeyMaterial: sharedSecret (256 bits),
     salt: "ROOT" (encoded as bytes),
     info: sessionId (encoded as bytes),
     length: 256 bits
   )
   ```

   - Root key serves as base for further derivation
   - Salt: Context identifier "ROOT"
   - Info: Session identifier (unique per session)

2. **Derive Send Key (Client A)**:

   ```
   sendKey_A = HKDF(
     inputKeyMaterial: rootKey (256 bits),
     salt: "SEND" (encoded as bytes),
     info: aliceId (encoded as bytes),
     length: 256 bits
   )
   ```

   - Client A uses this key to encrypt outgoing messages
   - Salt: Context identifier "SEND"
   - Info: Client A's user ID

3. **Derive Receive Key (Client A)**:

   ```
   recvKey_A = HKDF(
     inputKeyMaterial: rootKey (256 bits),
     salt: "RECV" (encoded as bytes),
     info: bobId (encoded as bytes),
     length: 256 bits
   )
   ```

   - Client A uses this key to decrypt incoming messages from Client B
   - Salt: Context identifier "RECV"
   - Info: Client B's user ID

4. **Derive Send Key (Client B)**:

   ```
   sendKey_B = HKDF(
     inputKeyMaterial: rootKey (256 bits),
     salt: "SEND" (encoded as bytes),
     info: bobId (encoded as bytes),
     length: 256 bits
   )
   ```

   - Client B uses this key to encrypt outgoing messages

5. **Derive Receive Key (Client B)**:
   ```
   recvKey_B = HKDF(
     inputKeyMaterial: rootKey (256 bits),
     salt: "RECV" (encoded as bytes),
     info: aliceId (encoded as bytes),
     length: 256 bits
   )
   ```
   - Client B uses this key to decrypt incoming messages from Client A

**Key Symmetry:**

- `sendKey_A = recvKey_B` (same key, different names)
- `sendKey_B = recvKey_A` (same key, different names)
- Both clients derive the same keys from the same root key

**Session Key Storage:**

- Session keys stored in IndexedDB (encrypted) on each client
- Keys associated with sessionId for retrieval
- Keys used for AES-256-GCM encryption/decryption of messages
- Keys remain valid until session ends or key rotation occurs

**Optional Keys (Future Enhancement):**

- Message authentication key (separate from encryption)
- Key rotation keys
- Forward secrecy keys

#### Step 6 — Key Confirmation

**Purpose:**

- Key confirmation ensures both parties derived the same session keys
- Prevents MITM attacks where attacker might have established separate sessions
- Provides cryptographic proof that key exchange completed successfully

**Client B Generates Key Confirmation (KEP_RESPONSE):**

1. **Compute Key Confirmation HMAC**:

   ```
   keyConfirmation = HMAC-SHA256(
     key: rootKey (256 bits),
     message: "CONFIRM:" + aliceId (string)
   )
   ```

   - Uses rootKey as HMAC key
   - Message includes peer's user ID for context
   - Result: 256-bit HMAC value

2. **Include in KEP_RESPONSE**:
   - Add `keyConfirmation` field to KEP_RESPONSE message
   - Encode HMAC as base64 for transmission
   - Send to Client A via server

**Client A Verifies Key Confirmation:**

1. **Receive KEP_RESPONSE**:

   - Client A receives KEP_RESPONSE message from Client B via WebSocket
   - Message includes signed ephemeral public key, signature, and key confirmation
   - Extracts `keyConfirmation` field (base64-encoded HMAC)

2. **Derive Session Keys** (if not already done):

   - Client A has already computed shared secret from Step 4
   - Client A has already derived session keys from Step 5:
     - rootKey (from shared secret)
     - sendKey_A (for encrypting outgoing messages)
     - recvKey_A (for decrypting incoming messages)

3. **Compute Expected Key Confirmation**:

   - Client A computes same HMAC using its derived rootKey:
     ```
     expectedConfirmation = HMAC-SHA256(
       key: rootKey (256 bits),
       message: "CONFIRM:" + aliceId (string)
     )
     ```

4. **Compare HMAC Values**:

   - Decode received `keyConfirmation` from base64 to ArrayBuffer
   - Compare with computed `expectedConfirmation` using constant-time comparison
   - Constant-time comparison prevents timing attacks (byte-by-byte comparison)
   - Comparison function: `crypto.subtle.timingSafeEqual()` or equivalent

5. **Verification Result**:
   - ✅ **Match**: Both parties derived same rootKey → Session established successfully
   - ❌ **Mismatch**: Keys differ → Possible MITM attack → Session rejected, logged to `invalid_signature.log`

**Client A Sends Key Confirmation Response (Optional Enhancement):**

1. **Generate Key Confirmation Message**:

   - Client A computes its own key confirmation HMAC:
     ```
     keyConfirmation_A = HMAC-SHA256(
       key: rootKey (256 bits),
       message: "CONFIRM:" + bobId (string)
     )
     ```
   - Creates signed confirmation message:
     ```json
     {
       "type": "KEY_CONFIRM",
       "sessionId": "session-abc123",
       "from": "aliceId",
       "to": "bobId",
       "keyConfirmation": <base64 HMAC>,
       "timestamp": <current timestamp>,
       "nonce": <random nonce>,
       "signature": <signed with IK_priv_A>
     }
     ```

2. **Sign Confirmation Message**:

   - Sign message payload using `IK_priv_A` (identity private key)
   - Signature provides non-repudiation and authenticity
   - Include signature in message for Client B to verify

3. **Send to Client B**:
   - Send via WebSocket: `socket.emit("kep:confirm", message)`
   - Server relays message to Client B
   - Client B verifies signature and key confirmation

**Key Confirmation Message Structure:**

Each key confirmation message includes:

- **sessionId**: Unique session identifier linking to the key exchange
- **Hash of Derived Key Material**: HMAC of rootKey proves both parties have same key
- **Timestamp**: Current timestamp for replay protection
- **Nonce**: Random nonce (16 bytes) for additional uniqueness
- **Signature**: Signed with sender's identity private key for authenticity

**Key Confirmation Flow:**

```
Client A                          Server                          Client B
    |                                |                                |
    |-- KEP_INIT (signed) ---------->|                                |
    |                                |-- KEP_INIT (relay) ----------->|
    |                                |                                |
    |                                |<-- KEP_RESPONSE (signed) ------|
    |<-- KEP_RESPONSE (relay) ------|                                |
    |                                |                                |
    | Computes sharedSecret          |                                |
    | Derives rootKey                |                                |
    | Verifies keyConfirmation ✓     |                                |
    |                                |                                |
    |-- KEY_CONFIRM (signed) ------->|                                |
    |                                |-- KEY_CONFIRM (relay) -------->|
    |                                |                                |
    |                                | Verifies signature ✓           |
    |                                | Verifies keyConfirmation ✓     |
    |                                |                                |
    | Session Established ✓          |                                | Session Established ✓
```

**Key Confirmation Properties:**

- **Confirms Key Agreement**: Both parties have the same rootKey
- **Prevents MITM**: Attacker cannot forge key confirmation without rootKey
- **Cryptographic Proof**: HMAC provides proof that both parties derived same keys
- **Final Verification**: Last step before session is considered established
- **Non-repudiation**: Signed confirmation messages provide proof of key exchange completion

**MITM Prevention:**

- If attacker intercepts and modifies ephemeral keys:
  - Signature verification fails (Step 3) → Attack detected early
- If attacker establishes separate sessions:
  - Key confirmation HMACs will differ → Attack detected in Step 6
  - Both parties reject session → No communication possible

**Session Establishment:**

- After successful key confirmation verification:
  - Session marked as "established" in sessionManager
  - Session keys (sendKey, recvKey) stored in IndexedDB
  - Session ready for encrypted messaging
  - Ephemeral keys discarded from memory (forward secrecy)
  - Session ID used for all subsequent encrypted messages

### 4. Replay & MITM Defense Explained (Text Version)

#### Nonce Usage

- **Purpose**: Prevent exact message replay
- **Generation**: Cryptographically random, 16 bytes
- **Storage**: Included in envelope, not validated server-side
- **Future**: Bloom filter for nonce tracking

#### Timestamp Acceptance Window

- **Window**: ±2 minutes (120,000 ms)
- **Validation**: `|currentTime - messageTimestamp| <= 2 minutes`
- **Rejection**: Messages outside window are rejected
- **Rationale**: Accounts for clock skew while preventing old message replay

#### Sequence Number Monotonicity

- **Rule**: `message.seq > lastSeq` (strictly increasing)
- **Storage**: Per session in IndexedDB
- **Rejection**: Out-of-order or duplicate sequences rejected
- **Update**: `lastSeq` updated only after successful decryption

#### Signature Validation

- **Purpose**: Verify ephemeral key authenticity
- **Process**: `verify(IK_pub, signature, ephPub_JWK)`
- **Failure**: Invalid signature → message rejected, security event logged
- **Protection**: Prevents MITM from injecting fake ephemeral keys

#### Why Unsigned DH is Vulnerable

- **Attack**: MITM can replace `EK_pub` with attacker's key
- **Result**: Both parties compute shared secret with attacker
- **Consequence**: Attacker can decrypt all messages

#### How Signed DH/ECDH Prevents MITM

- **Protection**: Identity keys sign ephemeral keys
- **Verification**: Peer verifies signature using known `IK_pub`
- **Result**: Attacker cannot forge signatures without `IK_priv`
- **Security**: Only legitimate user can sign with their identity key

#### How Replayed Messages are Rejected

1. **Timestamp Check**: Old messages (>2 min) rejected
2. **Sequence Check**: Duplicate or out-of-order sequences rejected
3. **Message ID Check**: Database uniqueness constraint prevents duplicates
4. **Nonce Check**: Client-side nonce tracking (future enhancement)
5. **Auth Tag Check**: Tampered messages fail decryption

### 5. Server Interaction Model (Metadata-only)

**Server Capabilities:**

- ✅ Relays public identity keys (`IK_pub`) via `/api/keys/:userId`
- ✅ Relays ephemeral public keys (`EK_pub`) in KEP messages
- ✅ Relays encrypted message envelopes (ciphertext, iv, authTag)
- ✅ Stores message metadata (sender, receiver, timestamp, seq, type)
- ✅ Routes messages to online recipients via WebSocket
- ✅ Queues messages for offline recipients

**Server Limitations:**

- ❌ Cannot decrypt messages (no access to session keys)
- ❌ Cannot read plaintext (only encrypted ciphertext)
- ❌ Cannot modify message content (auth tag prevents tampering)
- ❌ Cannot forge signatures (no access to private keys)
- ❌ Cannot decrypt files (no access to encryption keys)

**Server Storage:**

- **Public Keys**: `IK_pub` in `PublicKey` collection
- **Message Metadata**: `MessageMeta` collection (no ciphertext)
- **KEP Messages**: `KEPMessage` collection (metadata only)

**Server Verification:**

- Server does NOT verify signatures (client-side only)
- Server validates timestamp freshness (replay protection)
- Server enforces message ID uniqueness (duplicate prevention)
- Server logs security events (replay attempts, invalid messages)

### 6. Components to Show in a Diagram

#### Entities

- **Client A**: User device with identity keys, session keys, encryption/decryption
- **Client B**: User device with identity keys, session keys, encryption/decryption
- **Server**: Metadata relay + public key directory (MongoDB)
- **WebSocket Channel**: Real-time bidirectional communication (WSS)
- **Database**: MongoDB (stores metadata, public keys, message metadata)
- **Local Secure Key Store**: IndexedDB on each client (encrypted private keys, session keys)

#### Flows to Visualize

**Registration Flow:**

- User registration → Identity key generation → Public key upload → Server storage

**Auth Handshake:**

- Login → JWT token → WebSocket authentication → Identity verification

**Key Exchange:**

- Identity key lookup → Ephemeral key generation → KEP_INIT → Signature verification → KEP_RESPONSE → Shared secret computation → Session key derivation

**Key Confirmation:**

- Key confirmation HMAC generation → Verification → Session establishment

**Encrypted Message Sending:**

- Plaintext input → Session key retrieval → AES-GCM encryption → Envelope building → WebSocket transmission → Server relay → Recipient decryption

**File Encryption Workflow:**

- File selection → Chunking (256 KB) → Per-chunk encryption → FILE_META envelope → FILE_CHUNK envelopes → Sequential transmission → Reconstruction → Decryption

### 7. Requirements for Future Diagram Creation

A future protocol diagram MUST visualize:

**Key Materials:**

- Identity keys (`IK_priv`, `IK_pub`) with storage locations
- Ephemeral keys (`EK_priv`, `EK_pub`) generation and exchange
- Session keys (`rootKey`, `sendKey`, `recvKey`) derivation chain

**Signature Validation:**

- Identity key signing of ephemeral keys
- Signature verification process
- Signature fields in KEP messages

**ECDH Flows:**

- Ephemeral key exchange (A → B, B → A)
- Shared secret computation on both sides
- Symmetry of ECDH (both parties get same secret)

**HKDF Derivation:**

- Input: shared secret from ECDH
- Derivation chain: sharedSecret → rootKey → sendKey/recvKey
- Salt and info parameters for each step

**Session Keys:**

- Storage location (IndexedDB)
- Usage direction (sendKey for outgoing, recvKey for incoming)
- Key lifecycle (generation, usage, rotation placeholder)

**Encrypted Message Path:**

- Plaintext → Encryption (AES-GCM) → Envelope → WebSocket → Server → WebSocket → Decryption → Plaintext
- Show ciphertext, IV, authTag transmission
- Show metadata-only server storage

**File Chunk Encryption Route:**

- File → Chunking → Per-chunk encryption → Multiple envelopes → Sequential transmission → Reconstruction → Decryption → File

**Replay Protections:**

- Timestamp validation points
- Sequence number checks
- Message ID uniqueness enforcement
- Nonce inclusion (future validation)

**MITM Blocked Points:**

- Signature verification prevents key substitution
- Auth tag verification prevents message tampering
- Key confirmation ensures both parties have same keys

**Relevant Timestamps + Nonces:**

- Timestamp generation in KEP messages
- Timestamp validation windows
- Nonce generation and inclusion
- Sequence number management

**Diagram Must Show:**

- Clear separation between client-side (encryption/decryption) and server-side (relay only)
- No plaintext paths through server
- All cryptographic operations on client side
- Server as "dumb pipe" for encrypted data

## Testing

### Running Tests

```bash
# Run integration tests
npm test

# Run specific test suite
npm test -- integration/fullSystemTest.js
```

### Manual Testing Checklist

- [ ] User registration → identity key generation
- [ ] Login → private key loading
- [ ] Key exchange → session keys generated
- [ ] Message send → encrypted before transmission
- [ ] Message receive → decrypted only at client
- [ ] File upload → encrypted chunks only
- [ ] File download → proper decryption
- [ ] MITM simulation → unsigned fails, signed succeeds
- [ ] Replay simulation → messages rejected
- [ ] Invalid signature → logged and rejected
- [ ] Stale timestamp → rejected
- [ ] Sequence rewind → rejected

## Performance Benchmarks

Typical performance measurements:

- **Key Exchange**: < 100ms
- **Message Encryption**: < 10ms
- **Message Decryption**: < 10ms
- **File Encryption (1MB)**: < 100ms
- **File Decryption (1MB)**: < 100ms

_Note: Performance may vary based on hardware and network conditions._

## Documentation

### Protocol Documentation

- [Key Exchange Protocol](./docs/protocols/KEY_EXCHANGE_PROTOCOL.md)
- [Message Encryption Flow](./docs/protocols/MESSAGE_ENCRYPTION_FLOW.md)

### Deployment

- [Deployment Guide](./docs/deployment/DEPLOYMENT_GUIDE.md)

### Security

- [Threat Model (STRIDE)](./docs/THREAT_MODEL.md)
- [Phase 3 Crypto Design](./docs/cryptography/PHASE3_CRYPTO_DESIGN.md)
- [Phase 4 Messaging Design](./docs/PHASE4_MESSAGING_DESIGN.md)

### Demo

- [Demo Script](./integration/demoScripts/demo-script.md)

## Limitations

1. **Browser Security**: Relies on browser security model
2. **Key Storage**: Encrypted keys vulnerable to password theft
3. **Perfect Forward Secrecy**: Initial exchange uses identity keys
4. **Group Messaging**: Not yet implemented
5. **Message Deletion**: No secure deletion protocol
6. **Offline Support**: Limited offline message queuing

## Future Enhancements

1. **Perfect Forward Secrecy**: Ephemeral-only initial exchange
2. **Group Messaging**: Multi-party encryption
3. **Message Search**: Encrypted search (homomorphic encryption?)
4. **Key Recovery**: Optional key escrow mechanism
5. **Enhanced DoS Protection**: More sophisticated rate limiting
6. **Streaming Encryption**: For very large files
7. **Mobile Apps**: Native mobile implementations

### Threat Modeling (STRIDE) – Detailed Table

This table provides a comprehensive STRIDE analysis of threats specific to our E2EE messaging system and the mitigations implemented.

| Threat Category (STRIDE)                | Description                                                                                             | Where it can occur in our system                                 | Impact                                                                                           | Mitigations Implemented                                                                                                                                                                                                                                                                                                                                                    |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **S - Spoofing**                        |                                                                                                         |                                                                  |                                                                                                  |                                                                                                                                                                                                                                                                                                                                                                            |
| Fake user identities                    | Attacker creates account with stolen credentials or impersonates legitimate user                        | User registration endpoint, login endpoint                       | High - Attacker gains access to system and can participate in key exchanges                      | • JWT-based authentication with ECC ES256 signatures<br>• Password hashing with bcrypt (10 rounds)<br>• Email uniqueness validation<br>• Account activation status checks<br>• Refresh token rotation on each use                                                                                                                                                          |
| Fake public keys                        | Attacker uploads malicious public key to server's public key directory, replacing legitimate user's key | `/api/keys/upload` endpoint                                      | Critical - Attacker can intercept and decrypt messages intended for legitimate user              | • Public key upload requires authenticated user (JWT verification)<br>• Users can only upload/update their own public key<br>• Public key directory stores keys with user ID association<br>• Key verification during key exchange protocol                                                                                                                                |
| MITM intercepting DH keys               | Attacker intercepts ephemeral public keys during key exchange and replaces them with attacker's keys    | Key Exchange Protocol (KEP_INIT, KEP_RESPONSE) messages          | Critical - Attacker establishes separate sessions with both parties and can decrypt all messages | • Ephemeral keys signed with identity private keys (ECDSA P-256)<br>• Signature verification on all KEP messages<br>• Identity public keys fetched from trusted server directory<br>• Invalid signatures cause message rejection and logging                                                                                                                               |
| **T - Tampering**                       |                                                                                                         |                                                                  |                                                                                                  |                                                                                                                                                                                                                                                                                                                                                                            |
| Modifying ciphertext                    | Attacker intercepts encrypted message and modifies ciphertext or authentication tag                     | Message transmission via WebSocket or REST API                   | High - Modified messages may decrypt to garbage or attacker-controlled content                   | • AES-256-GCM authentication tags (128-bit) verify message integrity<br>• Invalid auth tags cause decryption to fail (OperationError)<br>• Auth tag verification is automatic during AES-GCM decryption<br>• Tampered messages are rejected and logged                                                                                                                     |
| Modifying public key records on server  | Attacker modifies public key directory entries in MongoDB                                               | MongoDB database, `/api/keys/upload` endpoint                    | Critical - Attacker could replace legitimate keys with malicious ones                            | • Public key upload requires authentication (JWT verification)<br>• Users can only modify their own public keys<br>• Server validates key ownership before allowing updates<br>• Key changes are logged for audit                                                                                                                                                          |
| Changing sequence numbers or timestamps | Attacker modifies sequence numbers or timestamps in message envelopes to bypass replay protection       | Message envelope during transmission                             | Medium - Could allow replay attacks or message reordering                                        | • Sequence numbers validated for strict monotonicity<br>• Timestamps validated for freshness (±2 minutes)<br>• Message ID uniqueness enforced in database<br>• Invalid sequence/timestamp causes message rejection<br>• Replay attempts logged to `replay_attempts.log`                                                                                                    |
| **R - Repudiation**                     |                                                                                                         |                                                                  |                                                                                                  |                                                                                                                                                                                                                                                                                                                                                                            |
| Users denying message sending           | User claims they did not send a message that appears to be from them                                    | Message metadata, audit logs                                     | Medium - Disputes over message authorship                                                        | • Digital signatures on all key exchange messages provide non-repudiation<br>• Message metadata includes sender ID and timestamp<br>• All security events logged with user ID and timestamp<br>• Audit trail in `message_metadata_access.log` and `msg_forwarding.log`<br>• Server stores message metadata with sender/receiver associations                               |
| Attackers injecting forged metadata     | Attacker creates fake message metadata to frame legitimate users                                        | Message metadata storage, WebSocket message forwarding           | High - Could create false evidence or disrupt trust                                              | • Message metadata includes authenticated sender ID (from JWT)<br>• Server validates sender identity before storing metadata<br>• WebSocket connections require JWT authentication<br>• Invalid sender IDs cause message rejection<br>• Metadata injection attempts logged                                                                                                 |
| **I - Information Disclosure**          |                                                                                                         |                                                                  |                                                                                                  |                                                                                                                                                                                                                                                                                                                                                                            |
| Metadata leakage                        | Server or logs expose information about who is communicating with whom                                  | MongoDB metadata storage, log files, WebSocket routing           | Medium - Reveals communication patterns and relationships                                        | • Server stores only minimal metadata (sessionId, sender, receiver, timestamp, seq, type)<br>• No plaintext content in metadata<br>• Logs sanitized to remove PII before AI processing<br>• Access to metadata requires authentication<br>• Metadata access logged to `message_metadata_access.log`                                                                        |
| Traffic pattern analysis                | Attacker analyzes message timing, frequency, or size patterns to infer communication content            | WebSocket traffic, message transmission patterns                 | Low-Medium - Could reveal communication patterns                                                 | • Messages encrypted with variable-length padding (future enhancement)<br>• File chunks standardized to 256KB to obscure file sizes<br>• Timestamps include random nonce to prevent correlation<br>• WebSocket traffic encrypted with WSS (TLS)                                                                                                                            |
| File size leakage                       | Attacker infers file content from encrypted file size                                                   | FILE_META envelope, file chunk sizes                             | Low - Could reveal approximate file types or sizes                                               | • File metadata encrypted separately from file content<br>• File chunks standardized to 256KB (pads smaller chunks)<br>• Multiple files of similar size produce similar encrypted sizes<br>• Server stores only chunk count, not individual chunk sizes                                                                                                                    |
| Plaintext exposure                      | Plaintext messages or keys exposed in logs, memory dumps, or server storage                             | Log files, server memory, database storage                       | Critical - Complete compromise of message confidentiality                                        | • No plaintext ever stored on server<br>• Server stores only encrypted ciphertext and metadata<br>• Logs never contain plaintext messages or keys<br>• Private keys stored encrypted in IndexedDB (password-derived encryption)<br>• Session keys stored encrypted in IndexedDB                                                                                            |
| **D - Denial of Service**               |                                                                                                         |                                                                  |                                                                                                  |                                                                                                                                                                                                                                                                                                                                                                            |
| Flooding key exchange requests          | Attacker sends many KEP_INIT or KEP_RESPONSE messages to exhaust server resources                       | Key exchange endpoints, WebSocket KEP handlers                   | Medium - Server resource exhaustion, legitimate users blocked                                    | • Rate limiting on authentication endpoints (10 requests per 15 minutes for AI endpoints)<br>• WebSocket connections require authentication<br>• Invalid KEP messages rejected early (before processing)<br>• KEP message validation includes timestamp freshness check<br>• Excessive invalid requests logged and can trigger IP blocking (future enhancement)            |
| Replaying many invalid messages         | Attacker replays captured messages repeatedly to flood system                                           | Message endpoints, WebSocket message handlers                    | Medium - Server processing overhead, log file growth                                             | • Replay detection via timestamp and sequence number validation<br>• Duplicate message IDs rejected at database level (unique constraint)<br>• Replay attempts logged but do not consume decryption resources<br>• Invalid messages rejected before decryption attempt<br>• Rate limiting prevents excessive request volume                                                |
| Disrupting WebSocket channels           | Attacker floods WebSocket connections with malformed data or excessive messages                         | WebSocket server, Socket.IO handlers                             | Medium - WebSocket server overload, legitimate connections disrupted                             | • WebSocket connections require JWT authentication<br>• Malformed messages rejected early in processing<br>• Message validation before forwarding to recipients<br>• Connection limits per user (future enhancement)<br>• WebSocket errors logged for monitoring                                                                                                           |
| **E - Elevation of Privilege**          |                                                                                                         |                                                                  |                                                                                                  |                                                                                                                                                                                                                                                                                                                                                                            |
| Bypassing authentication                | Attacker gains access to protected endpoints or WebSocket channels without valid credentials            | Authentication middleware, JWT verification, WebSocket auth      | Critical - Attacker gains unauthorized system access                                             | • All protected routes require JWT authentication (`requireAuth` middleware)<br>• JWT tokens signed with ECC ES256 (cannot be forged without private key)<br>• WebSocket connections verify JWT during handshake<br>• Invalid or expired tokens cause connection rejection<br>• Token refresh requires valid refresh token in HttpOnly cookie                              |
| Injecting forged signatures             | Attacker creates valid-looking signatures without possessing identity private key                       | Key exchange messages, key update messages                       | Critical - Attacker could impersonate users in key exchanges                                     | • Signatures use ECDSA P-256 with identity private keys<br>• Identity private keys never leave client (stored encrypted in IndexedDB)<br>• Signature verification uses identity public keys from trusted directory<br>• Invalid signatures cause message rejection and logging to `invalid_signature.log`<br>• Signature verification happens before key exchange proceeds |
| Exploiting weak key verification        | Attacker exploits vulnerabilities in key verification logic to accept malicious keys                    | Key exchange protocol, signature verification, public key import | Critical - Attacker could establish sessions with malicious keys                                 | • Public keys validated for correct format (JWK, P-256 curve)<br>• Signature verification uses Web Crypto API (cryptographically secure)<br>• Key exchange requires both KEP_INIT and KEP_RESPONSE with valid signatures<br>• Key confirmation HMAC verifies both parties derived same keys<br>• Invalid keys cause key exchange failure and logging                       |

**Legend:**

- **Impact Levels**: Critical (complete system compromise), High (significant data/security breach), Medium (moderate impact), Low (minimal impact)
- **Mitigation Status**: All listed mitigations are implemented in the current system
- **Logging**: Security events are logged to appropriate log files in `server/logs/` directory

## Security Warnings

⚠️ **Important Security Notes**:

- This is an educational project. Use in production at your own risk.
- Self-signed certificates are for development only. Use real certificates in production.
- Private keys are stored encrypted but still vulnerable to password theft.
- Browser extensions can potentially access keys.
- XSS attacks could compromise key storage.

## Contributing

This project was developed as a learning exercise. Contributions and improvements are welcome!

## License

ISC
