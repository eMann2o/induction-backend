const mongoose = require('mongoose');

const testAnswerSchema = new mongoose.Schema({
  question: { type: mongoose.Schema.Types.ObjectId, ref: 'Question', required: true },
  selectedAnswer: { type: Boolean, required: true }, // trainee choice true/false
  isCorrect: { type: Boolean, required: true }       // computed at grading
}, { _id: false });

const testAttemptSchema = new mongoose.Schema({
  trainee: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  session: { type: mongoose.Schema.Types.ObjectId, ref: 'Session', required: true },

  answers: [ testAnswerSchema ],

  score: { type: Number, default: 0 },       // number of correct answers
  totalQuestions: { type: Number, default: 0 },

  status: { type: String, enum: ['passed', 'failed'], required: true },

  attemptNumber: { type: Number, default: 1 },
  submittedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Attempt', testAttemptSchema);
