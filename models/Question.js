const mongoose = require('mongoose');

const questionSchema = new mongoose.Schema({
  training: { type: mongoose.Schema.Types.ObjectId, ref: 'Training', required: true },
  questionText: { type: String, required: true },
  correctAnswer: { type: Boolean, required: true }, // true/false

  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Question', questionSchema);
