const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  isProtected: { type: Boolean, required: true },
  role: { type: String, enum: ['user', 'assistant', 'system'], required: true },
  content: { type: String, required: true },
  isError: { type: Boolean, default: false },
  security: { type: Object, default: null },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  organizationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization', default: null, index: true },
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.models.MessageLog || mongoose.model('MessageLog', messageSchema);
