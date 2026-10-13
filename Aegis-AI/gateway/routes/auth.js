const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Organization = require('../models/Organization');
const { JWT_SECRET, authenticateToken } = require('../middleware/auth');

const ADMIN_REGISTRATION_SECRET = process.env.ADMIN_REGISTRATION_SECRET || 'aegis-admin-provision-2026';

// Helper to ensure a default organization exists
async function getOrCreateDefaultOrg(orgName) {
  const name = (orgName && orgName.trim()) || 'Acme Cybersecurity Ltd';
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') || 'default-org';
  
  let org = await Organization.findOne({ slug });
  if (!org) {
    org = await new Organization({ name, slug }).save();
  }
  return org;
}

// POST /api/auth/register
router.post('/register', async (req, res) => {
  try {
    const { name, email, password, organizationName, adminSecret } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists.' });
    }

    // Role cannot be self-escalated to admin without valid adminSecret
    let role = 'employee';
    if (adminSecret && adminSecret === ADMIN_REGISTRATION_SECRET) {
      role = 'admin';
    }

    const org = await getOrCreateDefaultOrg(organizationName);
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await new User({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      role,
      organizationId: org._id,
      organizationName: org.name
    }).save();

    const token = jwt.sign(
      { userId: user._id, role: user.role, organizationId: org._id },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        organizationId: org._id,
        organizationName: org.name
      }
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed: ' + err.message });
  }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required.' });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Backward compatibility: ensure legacy users have an organization assigned
    if (!user.organizationId) {
      const defaultOrg = await getOrCreateDefaultOrg('Acme Cybersecurity Ltd');
      user.organizationId = defaultOrg._id;
      user.organizationName = defaultOrg.name;
      if (!user.role) user.role = 'employee';
      await user.save();
    }

    const token = jwt.sign(
      { userId: user._id, role: user.role || 'employee', organizationId: user.organizationId },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role || 'employee',
        organizationId: user.organizationId,
        organizationName: user.organizationName || 'Acme Cybersecurity Ltd'
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed: ' + err.message });
  }
});

// GET /api/auth/me
router.get('/me', authenticateToken, async (req, res) => {
  res.json({ user: req.user });
});

// POST /api/auth/provision-admin (controlled admin promotion for setup/testing)
router.post('/provision-admin', authenticateToken, async (req, res) => {
  const { adminSecret, targetEmail } = req.body;
  if (adminSecret !== ADMIN_REGISTRATION_SECRET) {
    return res.status(403).json({ error: 'Invalid admin provision secret.' });
  }

  const emailToPromote = targetEmail ? targetEmail.toLowerCase().trim() : req.user.email;
  const user = await User.findOne({ email: emailToPromote });
  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }

  user.role = 'admin';
  await user.save();

  res.json({ message: `User ${user.email} promoted to admin.`, role: user.role });
});

module.exports = router;
