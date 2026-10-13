const mongoose = require('mongoose');

const promptShieldIncidentSchema = new mongoose.Schema({
  eventId: { type: String, required: true, unique: true, index: true },
  organizationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
  employeeId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  employeeName: { type: String, required: true },
  employeeEmail: { type: String, required: true },
  occurredAt: { type: Date, required: true, default: Date.now },
  receivedAt: { type: Date, default: Date.now },
  sourcePlatform: { type: String, default: 'chatgpt' },
  ruleId: { type: String, required: true },
  ruleName: { type: String, default: '' },
  severity: { type: String, enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], required: true },
  action: { type: String, enum: ['BLOCKED', 'WARNED', 'REDACTED', 'ALLOWED'], required: true },
  detectorVersion: { type: String, default: '1.0.0' },
  policyVersion: { type: String, default: '1.0.0' },
  eventType: { type: String, default: 'detection' },
  sanitizedMetadata: {
    promptLengthChars: { type: Number, default: 0 },
    matchCount: { type: Number, default: 1 },
    isCompanyRule: { type: Boolean, default: false },
    companyAction: { type: String, default: null },
    explanation: { type: String, default: '' }
  }
}, { timestamps: true });

// Compound indexes for fast filtered searches on Employee Reports & Admin Dashboard
promptShieldIncidentSchema.index({ organizationId: 1, occurredAt: -1 });
promptShieldIncidentSchema.index({ employeeId: 1, occurredAt: -1 });
promptShieldIncidentSchema.index({ organizationId: 1, severity: 1 });
promptShieldIncidentSchema.index({ organizationId: 1, action: 1 });

module.exports = mongoose.models.PromptShieldIncident || mongoose.model('PromptShieldIncident', promptShieldIncidentSchema);
