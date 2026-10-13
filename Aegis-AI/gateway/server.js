require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const { JWT_SECRET } = require('./middleware/auth');

// Routers
const authRouter = require('./routes/auth');
const historyRouter = require('./routes/history');
const createChatRouter = require('./routes/chat');
const createExtensionRouter = require('./routes/extension');
const reportsRouter = require('./routes/reports');
const adminRouter = require('./routes/admin');
const policiesRouter = require('./routes/policies');
const { router: analyticsRouter } = require('./routes/analytics');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"]
  }
});

// Connect to MongoDB
const MONGO_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/aegis_analytics';
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB Atlas / Remote Database!'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err.message));

// Socket.IO Organization Scoping & Telemetry
io.on('connection', (socket) => {
  // Scoped room enrollment for authenticated clients
  const token = socket.handshake.auth?.token || socket.handshake.query?.token;
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.organizationId) {
        socket.join(`org_${decoded.organizationId}`);
      }
    } catch (e) {
      // Guest demo connection
    }
  }

  socket.on('join_org', (data) => {
    if (data?.token) {
      try {
        const decoded = jwt.verify(data.token, JWT_SECRET);
        if (decoded.organizationId) {
          socket.join(`org_${decoded.organizationId}`);
        }
      } catch (e) {}
    }
  });
});

// Mount API Routes
app.use('/api/auth', authRouter);
app.use('/api/history', historyRouter);
app.use('/api/chat', createChatRouter(io));
app.use('/api/extension', createExtensionRouter(io));
app.use('/api/reports', reportsRouter);
app.use('/api/admin', adminRouter);
app.use('/api/policies', policiesRouter);
app.use('/api/analytics', analyticsRouter);

// Root endpoint with service manifest
app.get('/', (req, res) => {
  res.json({
    status: 'online',
    name: 'Aegis-AI Security Gateway',
    version: '1.0.0',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    endpoints: {
      health: '/api/health',
      auth: '/api/auth',
      history: '/api/history',
      chat: '/api/chat',
      extension: '/api/extension',
      reports: '/api/reports',
      admin: '/api/admin',
      policies: '/api/policies',
      analytics: '/api/analytics'
    }
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Aegis-AI Security Gateway',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString()
  });
});

const PORT = process.env.PORT || 4000;

// Graceful EADDRINUSE error handling
server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n❌ [STARTUP FAILURE] Port ${PORT} is already occupied by another process.`);
    console.error(`👉 Diagnostic hint: Run 'netstat -ano | findstr :${PORT}' and 'tasklist /FI "PID eq <PID>"' to inspect the occupying process.`);
    console.error(`👉 Or configure an alternative port via PORT=<port> in gateway/.env\n`);
    process.exit(1);
  } else {
    console.error('❌ Server startup error:', err);
    process.exit(1);
  }
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`✅ Aegis.AI Gateway successfully listening on http://localhost:${PORT}`);
  });
}

module.exports = { app, server, io };
