const mongoose = require('mongoose');

const trainingSessionSchema = new mongoose.Schema({
  training: { type: mongoose.Schema.Types.ObjectId, ref: 'Training', required: true },
  facilitator: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  trainees: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],

  // Link to the specific QuestionSet snapshot
  questionSet: { type: mongoose.Schema.Types.ObjectId, ref: 'QuestionSet', required: true },
  questionSetVersion: { type: Number, required: true },

  // Session lifecycle
  status: { 
    type: String, 
    enum: ['scheduled', 'active', 'completed'], 
    default: 'scheduled' 
  },
  startTime: { type: Date },
  endTime: { type: Date },

  // QR attendance
  qrCodeToken: { type: String, default: null },

  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Session', trainingSessionSchema);
