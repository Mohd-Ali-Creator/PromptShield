const mongoose = require('mongoose');

const organizationSchema = new mongoose.Schema({
  name: { type: String, required: true },
  slug: { type: String, required: true, unique: true, index: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.models.Organization || mongoose.model('Organization', organizationSchema);
