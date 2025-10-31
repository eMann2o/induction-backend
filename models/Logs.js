const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
  actor: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, 
  action: { type: String, required: true }, 
  details: { type: mongoose.Schema.Types.Mixed }, // flexible (object/JSON)
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Log', logSchema);
