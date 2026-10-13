const mongoose = require('mongoose');

const policyAuditLogSchema = new mongoose.Schema({
  organizationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  actorEmail: { type: String, required: true },
  actionType: { type: String, required: true }, // 'CREATE_RULE', 'UPDATE_RULE', 'TOGGLE_RULE', 'DELETE_RULE'
  ruleId: { type: String, required: true },
  ruleName: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  details: { type: String, default: '' }
});

policyAuditLogSchema.index({ organizationId: 1, timestamp: -1 });

module.exports = mongoose.models.PolicyAuditLog || mongoose.model('PolicyAuditLog', policyAuditLogSchema);
