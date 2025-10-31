const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },

  email: {
    type: String,
    unique: true,
    sparse: true,
    required: function() {
      return this.role !== 'trainee';
    }
  },

  phoneNumber: {
    type: String,
    unique: true,
    sparse: true,
    required: function() {
      return this.role === 'trainee';
    }
  },

  password: {
    type: String,
    required: function() {
      return this.role !== 'trainee';
    }
  },

  department: String,

  role: {
    type: String,
    required: true,
    enum: ['trainee', 'facilitator', 'hr', 'hse', 'superadmin']
  },

  status: {
    type: String,
    default: 'active',
    enum: ['active', 'inactive']
  },
}, { timestamps: true });

userSchema.pre('save', function(next) {
  if (this.role === 'trainee') {
    this.set('email', undefined, { strict: false });
    this.markModified('email');
  }
  next();
});

module.exports = mongoose.model('User', userSchema);
