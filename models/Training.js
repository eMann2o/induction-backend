const mongoose = require('mongoose');

const trainingSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    department: { type: String },

    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // HSE
    passMark: { type: Number, required: true }, // percent threshold

    createdAt: { type: Date, default: Date.now },
    currentQuestionSet: { type: mongoose.Schema.Types.ObjectId, ref: 'QuestionSet' },
    currentVersion: { type: Number, default: 1 }
});

module.exports = mongoose.model('Training', trainingSchema);
