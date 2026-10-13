const mongoose = require('mongoose');

const companyRuleSchema = new mongoose.Schema({
  organizationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
  id: { type: String, required: true },
  name: { type: String, required: true },
  description: { type: String, default: '' },
  patternType: { type: String, enum: ['exact', 'regex'], required: true },
  pattern: { type: String, required: true },
  severity: { type: String, enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], required: true },
  action: { type: String, enum: ['block', 'warn', 'redact'], required: true },
  enabled: { type: Boolean, default: true },
  version: { type: Number, default: 1 },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  updatedAt: { type: Date, default: Date.now }
});

companyRuleSchema.index({ organizationId: 1, id: 1 }, { unique: true });

module.exports = mongoose.models.CompanyRule || mongoose.model('CompanyRule', companyRuleSchema);
