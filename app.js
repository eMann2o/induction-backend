require('dotenv').config();
const express = require('express');
const router = express.Router();
const app = express();
const mongoose = require('mongoose');
const connectDB = require('./db');
const bcrypt = require('bcrypt');
const authorize = require('./auth/auth');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const QuestionSet = require('./models/QuestionSet');
const Session = require('./models/Session');
const Question = require('./models/Question');
const Log = require('./models/Logs');
const Attempt = require('./models/Attempts');
const Training = require('./models/Training');
const crypto = require('crypto');
const cors =require('cors');

const path = require('path');
app.listen(3000);

app.use(express.static(path.join(__dirname, 'public'))); //middleware to serve static files
app.use(express.urlencoded({ extended: true }));//middleware to access urlencoded form data

app.use(express.json());                         // handles application/json


/* --- CORS Configuration --- */
app.use(
  cors({
    origin: process.env.CORS_ORIGIN, // your React dev server
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  })
);

app.use(express.json());

//Connect to database
connectDB();

module.exports = router;

//login
app.post('/login', async (req, res) => {
    try {
        // Enforce JSON only
        if (!req.is('application/json')) {
            return res.status(415).json({
                success: false,
                message: 'Content-Type must be application/json'
            });
        }

        const { email, password } = req.body || {};

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User does not exist'
            });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({
                success: false,
                message: 'Invalid password'
            });
        }

        const payload = {
            id: user._id,
            name: user.name,
            role: user.role,
        };

        const token = jwt.sign(payload, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRES_IN,
        });

        return res.status(200).json({
            success: true,
            message: 'Login successful',
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                status: user.status,
                token,
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({
            success: false,
            message: error.message || 'Server error'
        });
    }
});


// //logout
// app.post('/logout', (req, res) => {
//     return res.status(200).json({
//         success: true,
//         message: 'Logged out successfully.'
//     });
// });

//trainee login

//Trainee login
// Trainee login via phone after scanning QR

app.post('/sessions/:id/login', async (req, res) => {
  try {
    const { id } = req.params;
    const { phone } = req.body;

    if (!phone) {
      return res.status(400).json({
        success: false,
        message: 'Phone number is required'
      });
    }

    // 1. Ensure session is active
    const session = await Session.findOne({
      _id: id,
      status: 'active'
    }).populate('trainees', 'name phone email role active');

    if (!session) {
      return res.status(404).json({
        success: false,
        message: 'Session not found or inactive'
      });
    }

    // 2. Find user with matching phone number among trainees
    const trainee = session.trainees.find(
      t => t.phone === phone && t.role === 'trainee' && t.active
    );

    if (!trainee) {
      return res.status(403).json({
        success: false,
        message: 'This phone number is not enrolled or not active in the session'
      });
    }

    // 3. Issue JWT for subsequent API requests
    const loginToken = jwt.sign(
      {
        userId: trainee._id,
        sessionId: id,
        role: trainee.role
      },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );

    return res.status(200).json({
      success: true,
      message: 'Login successful',
      trainee: {
        id: trainee._id,
        name: trainee.name,
        phone: trainee.phone,
        email: trainee.email
      },
      token: loginToken
    });

  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || 'Server error'
    });
  }
});

//create user
app.post('/user-add', authorize(['superadmin', 'hr']), async (req, res) => {
  try {
    // Enforce JSON content type
    if (!req.is('application/json')) {
      return res.status(415).json({
        success: false,
        message: 'Content-Type must be application/json'
      });
    }

    const { name, email, phoneNumber, department, role, password } = req.body || {};

    // ✅ Basic validation
    if (!name || !role) {
      return res.status(400).json({
        success: false,
        message: 'Name and role are required'
      });
    }

    // ✅ Restrict HR
    if (req.user.role === 'hr' && role !== 'trainee') {
      return res.status(403).json({
        success: false,
        message: 'HR can only create trainee accounts'
      });
    }

    let hashedPassword;

    // ✅ Validation for non-trainees
    if (role !== 'trainee') {
      if (!email || !password) {
        return res.status(400).json({
          success: false,
          message: 'Email and password are required for staff accounts'
        });
      }

      hashedPassword = await bcrypt.hash(password, 10);
    } 
    // ✅ Validation for trainees
    else {
      if (!phoneNumber || !department) {
        return res.status(400).json({
          success: false,
          message: 'Phone number and department are required for trainees'
        });
      }
    }

    // ✅ Check for existing email or phone conflicts before saving
    const conflict = await User.findOne({
      $or: [
        role !== 'trainee' ? { email } : null,
        role === 'trainee' ? { phoneNumber } : null
      ].filter(Boolean)
    });

    if (conflict) {
      return res.status(409).json({
        success: false,
        message: role === 'trainee'
          ? 'A user with this phone number already exists'
          : 'A user with this email already exists'
      });
    }

    // ✅ Build user data safely
    const newUser = new User({
      name,
      email: role !== 'trainee' ? email : undefined,
      phoneNumber: role === 'trainee' ? phoneNumber : undefined,
      department: role === 'trainee' ? department : undefined,
      role,
      password: hashedPassword
    });

    // ✅ Save safely
    await newUser.save();

    return res.status(201).json({
      success: true,
      message: 'User created successfully',
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        phoneNumber: newUser.phoneNumber,
        department: newUser.department,
        role: newUser.role,
        status: newUser.status
      }
    });
  } catch (error) {
    // ✅ Handle duplicate key and general errors gracefully
    if (error.code === 11000) {
      const duplicateField = Object.keys(error.keyPattern || {})[0];
      return res.status(409).json({
        success: false,
        message: `Duplicate value for ${duplicateField}. This ${duplicateField} already exists.`
      });
    }

    return res.status(500).json({
      success: false,
      message: error.message || 'Server error'
    });
  }
});


//list all users
app.get('/users', authorize(['superadmin', 'hr', 'hse', 'facilitator']), async (req, res) => {
    try {
        let users;

        switch (req.user.role) {
            case 'superadmin': 
                users = await User.find().select('-password');
                break;

            case 'hr': 
                users = await User.find({ role: { $ne: 'superadmin' } }).select('-password');
                break;

            case 'hse': 
                users = await User.find({ role: { $in: ['facilitator', 'trainee'] } }).select('-password');
                break;

            case 'facilitator': 
                const facilitatorId = req.user.id;

                const sessions = await Session.find({ facilitator: facilitatorId })
                    .populate('trainees', '-password');
 
                let traineeMap = new Map();
                sessions.forEach(session => {
                    session.trainees.forEach(t => {
                        traineeMap.set(t._id.toString(), t);
                    });
                });

                users = Array.from(traineeMap.values());
                break;

            default:
                return res.status(403).json({
                    success: false,
                    message: 'Not authorized to view users'
                });
        }

        return res.status(200).json({
            success: true,
            count: users.length,
            users
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message || 'Server error'
        });
    }
});

// UPDATE user info
app.put('/users/:id', authorize(['superadmin', 'hr', 'hse']), async (req, res) => {
    try {
        const { id } = req.params;
        const { name, email, phoneNumber, department, role, password, status } = req.body || {};
 
        const targetUser = await User.findById(id);
        if (!targetUser) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
 
        if (req.user.role === 'hr' && !['hse', 'trainee'].includes(targetUser.role)) {
            return res.status(403).json({
                success: false,
                message: 'HR can only update HSE or trainee accounts'
            });
        }

        if (req.user.role === 'hse' && targetUser.role !== 'facilitator') {
            return res.status(403).json({
                success: false,
                message: 'HSE can only update facilitator accounts'
            });
        }
 
        const updateData = {};

        if (name) updateData.name = name;
        if (role) { 
            if (req.user.role === 'hr' && !['hse', 'trainee'].includes(role)) {
                return res.status(403).json({
                    success: false,
                    message: 'HR can only set role to HSE or trainee'
                });
            }
            if (req.user.role === 'hse' && role !== 'facilitator') {
                return res.status(403).json({
                    success: false,
                    message: 'HSE can only set role to facilitator'
                });
            }
            updateData.role = role;
        }
        if (email && targetUser.role !== 'trainee') updateData.email = email;
        if (phoneNumber && targetUser.role === 'trainee') updateData.phoneNumber = phoneNumber;
        if (department && targetUser.role === 'trainee') updateData.department = department;
        if (typeof status !== 'undefined') updateData.status = status;

        if (password) {
            updateData.password = await bcrypt.hash(password, 10);
        }

        const updatedUser = await User.findByIdAndUpdate(id, updateData, { new: true }).select('-password');

        return res.status(200).json({
            success: true,
            message: 'User updated successfully',
            user: updatedUser
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message || 'Server error'
        });
    }
});

// TOGGLE trainee's status 
app.patch('/users/:id/status', authorize(['superadmin', 'hr']), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.role !== 'trainee') {
      return res.status(400).json({
        success: false,
        message: 'Only trainees can have their status toggled'
      });
    }

    // Toggle the 'status' field, not 'active'
    user.status = user.status === 'active' ? 'inactive' : 'active';
    await user.save();

    return res.status(200).json({
      success: true,
      message: `Trainee status updated to ${user.status}`,
      user: {
        id: user._id,
        name: user.name,
        phoneNumber: user.phoneNumber,
        department: user.department,
        role: user.role,
        status: user.status
      }
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || 'Server error'
    });
  }
});


// GET logged-in user's profile
app.get('/me', authorize(), async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        return res.status(200).json({
            success: true,
            user
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message || 'Server error'
        });
    }
});

// DELETE a user
app.delete('/users/:id', authorize(['superadmin', 'hr', 'hse']), async (req, res) => {
    try {
        const user = await User.findById(req.params.id);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
 
        if (req.user.role === 'hr' && user.role !== 'trainee') {
            return res.status(403).json({
                success: false,
                message: 'HR can only delete trainees'
            });
        }

        if (req.user.role === 'hse' && user.role !== 'facilitator') {
            return res.status(403).json({
                success: false,
                message: 'HSE can only delete facilitators'
            });
        }
 
        if (req.user.id === user.id && req.user.role !== 'superadmin') {
            return res.status(403).json({
                success: false,
                message: 'You cannot delete your own account'
            });
        }

        await User.findByIdAndDelete(req.params.id);

        return res.status(200).json({
            success: true,
            message: 'User deleted successfully',
            deletedUser: {
                id: user._id,
                name: user.name,
                role: user.role,
                email: user.email,
                phoneNumber: user.phoneNumber
            }
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message || 'Server error'
        });
    }
});

// GET a single user by ID
app.get('/users/:id', authorize(['superadmin', 'hr', 'hse', 'facilitator']), async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Role-based access control (facilitator can only view trainees they manage)
    if (req.user.role === 'facilitator') {
      const sessions = await Session.find({ facilitator: req.user.id }).populate('trainees', '_id');
      const traineeIds = sessions.flatMap(s => s.trainees.map(t => t._id.toString()));
      if (!traineeIds.includes(user._id.toString())) {
        return res.status(403).json({ success: false, message: 'Not authorized to view this user' });
      }
    }

    return res.status(200).json({
      success: true,
      user
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || 'Server error'
    });
  }
});

// CREATE a training  
app.post('/trainings', authorize(['superadmin', 'hse']), async (req, res) => {
    try {
        // Enforce JSON only
        if (!req.is('application/json')) {
            return res.status(415).json({
                success: false,
                message: 'Content-Type must be application/json'
            });
        }

        const { title, description, passMark } = req.body || {};

        if (!title || !passMark) {
            return res.status(400).json({
                success: false,
                message: 'Training title and passMark are required'
            });
        }
 
        if (passMark < 1) {
            return res.status(400).json({
                success: false,
                message: 'Pass mark must be at least 1 question'
            });
        }
 
        const newTraining = new Training({
            title,
            description,
            passMark,
            currentVersion: 1
        });
        await newTraining.save();
 
        const questionSet = new QuestionSet({
            training: newTraining._id,
            version: 1,
            questions: [],
            createdBy: req.user.id
        });
        await questionSet.save();
 
        newTraining.currentQuestionSet = questionSet._id;
        await newTraining.save();

        return res.status(201).json({
            success: true,
            message: 'Training created successfully',
            training: {
                id: newTraining._id,
                title: newTraining.title,
                description: newTraining.description,
                passMark: newTraining.passMark,
                currentVersion: newTraining.currentVersion,
                currentQuestionSet: newTraining.currentQuestionSet,
                createdAt: newTraining.createdAt
            }
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message || 'Server error'
        });
    }
});

// LIST trainings (role-specific visibility)
app.get('/trainings', authorize(['superadmin', 'hr', 'hse', 'facilitator']), async (req, res) => {
    try {
        let trainings = [];

        if (['superadmin', 'hr', 'hse'].includes(req.user.role)) {            
            trainings = await Training.find()
                .populate('currentQuestionSet', 'version')
                .lean();
        } else if (req.user.role === 'facilitator') {
            const sessions = await Session.find({ facilitator: req.user.id })
                .populate('training', 'title description passMark currentVersion currentQuestionSet createdAt')
                .populate('training.currentQuestionSet', 'version')
                .lean();
            trainings = sessions.map(s => ({
                ...s.training,
                sessionDate: s.date 
            }));
        }

        return res.status(200).json({
            success: true,
            count: trainings.length,
            trainings
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message || 'Server error'
        });
    }
});

// GET a specific training by ID
app.get('/trainings/:id', authorize(['superadmin', 'hr', 'hse', 'facilitator']), async (req, res) => {
    try {
        const trainingId = req.params.id;

        let training = null;

        if (['superadmin', 'hr', 'hse'].includes(req.user.role)) {
            training = await Training.findById(trainingId)
                .populate('currentQuestionSet', 'version')
                .lean();
        } else if (req.user.role === 'facilitator') {
            const session = await Session.findOne({
                facilitator: req.user.id,
                training: trainingId
            })
                .populate('training', 'title description passMark currentVersion currentQuestionSet createdAt')
                .populate('training.currentQuestionSet', 'version')
                .lean();

            if (session) {
                training = {
                    ...session.training,
                    sessionDate: session.date
                };
            }
        }

        if (!training) {
            return res.status(403).json({
                success: false,
                message: 'Not authorized to access this training or training not found'
            });
        }

        return res.status(200).json({
            success: true,
            training
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message || 'Server error'
        });
    }
});

// UPDATE a training
app.put('/trainings/:id', authorize(['superadmin', 'hse']), async (req, res) => {
    try {
        // Enforce JSON only
        if (!req.is('application/json')) {
            return res.status(415).json({
                success: false,
                message: 'Content-Type must be application/json'
            });
        }

        const trainingId = req.params.id;
        const { title, description, passMark } = req.body || {};

        const training = await Training.findById(trainingId);
        if (!training) {
            return res.status(404).json({
                success: false,
                message: 'Training not found'
            });
        }
 
        if (title) training.title = title;
        if (description) training.description = description;

        if (typeof passMark !== 'undefined') {
            if (passMark < 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Pass mark must be a positive number'
                });
            }
            training.passMark = passMark;
        }

        await training.save();

        return res.status(200).json({
            success: true,
            message: 'Training updated successfully',
            training: {
                id: training._id,
                title: training.title,
                description: training.description,
                passMark: training.passMark,
                currentVersion: training.currentVersion,
                updatedAt: training.updatedAt
            }
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message || 'Server error'
        });
    }
});

// DELETE a training
app.delete('/trainings/:id', authorize(['superadmin', 'hse']), async (req, res) => {
    try {
        const trainingId = req.params.id;

        const training = await Training.findById(trainingId);
        if (!training) {
            return res.status(404).json({
                success: false,
                message: 'Training not found'
            });
        }
        const sessions = await Session.findOne({ training: trainingId });
        if (sessions) {
            return res.status(400).json({
                success: false,
                message: 'Cannot delete training with active sessions. Consider archiving instead.'
            });
        }

        await Training.findByIdAndDelete(trainingId);

        return res.status(200).json({
            success: true,
            message: 'Training deleted successfully'
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message || 'Server error'
        });
    }
});

// ADD questions to a training
app.post('/trainings/:id/questions', authorize(['superadmin', 'hse']), async (req, res) => {
    try {
      const trainingId = req.params.id;
      const { questions } = req.body || {};

      if (!Array.isArray(questions) || questions.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'At least one question is required',
        });
      }

      // Ensure all correctAnswer values are Boolean
      for (const q of questions) {
        if (typeof q.correctAnswer !== 'boolean') {
          return res.status(400).json({
            success: false,
            message: 'Each correctAnswer must be true or false (Boolean)',
          });
        }
      }

      const training = await Training.findById(trainingId);
      if (!training) {
        return res.status(404).json({
          success: false,
          message: 'Training not found',
        });
      }

      const createdQuestions = await Question.insertMany(
        questions.map((q) => ({
          training: training._id,
          questionText: q.text,
          correctAnswer: q.correctAnswer,
        }))
      );

      const questionIds = createdQuestions.map((q) => q._id);

      const questionSet = new QuestionSet({
        training: training._id,
        version: training.currentVersion + 1,
        questions: questionIds,
        createdBy: req.user._id,
      });

      await questionSet.save();

      training.currentQuestionSet = questionSet._id;
      training.currentVersion = questionSet.version;
      await training.save();

      return res.status(201).json({
        success: true,
        message: 'Questions added successfully',
        training: {
          id: training._id,
          title: training.title,
          currentVersion: training.currentVersion,
          questionSetId: training.currentQuestionSet,
        },
        createdQuestions,
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: error.message || 'Server error',
      });
    }
  }
);

// CREATE a training session
app.post('/sessions', authorize(['superadmin', 'hr', 'hse']), async (req, res) => {
    try {
      const { trainingId, facilitatorId, traineeIds } = req.body || {};

      // Validate required fields
      if (!trainingId || !facilitatorId) {
        return res.status(400).json({
          success: false,
          message: 'Training ID and facilitator are required',
        });
      }

      // Normalize traineeIds
      let normalizedTrainees = [];
      if (traineeIds) {
        if (Array.isArray(traineeIds)) {
          normalizedTrainees = traineeIds;
        } else if (typeof traineeIds === 'string') {
          normalizedTrainees = [traineeIds];
        } else {
          return res.status(400).json({
            success: false,
            message: 'traineeIds must be a string or an array of strings',
          });
        }
      }

      // Validate training
      const training = await Training.findById(trainingId);
      if (!training) {
        return res.status(404).json({
          success: false,
          message: 'Training not found',
        });
      }

      // Validate facilitator
      const facilitator = await User.findById(facilitatorId);
      if (!facilitator || facilitator.role !== 'facilitator') {
        return res.status(400).json({
          success: false,
          message: 'Facilitator not valid',
        });
      }

      // Create session
      const newSession = new Session({
        training: trainingId,
        facilitator: facilitatorId,
        trainees: normalizedTrainees,
        questionSet: training.currentQuestionSet,
        questionSetVersion: training.currentVersion,
      });

      await newSession.save();

      return res.status(201).json({
        success: true,
        message: 'Training session created successfully',
        session: {
          id: newSession._id,
          training: training.title,
          facilitator: facilitator.name,
          trainees: newSession.trainees,
          questionSetVersion: newSession.questionSetVersion,
        },
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: error.message || 'Server error',
      });
    }
  }
);

// GET a specific session with full details
app.get('/sessions/:id', authorize(['superadmin', 'hr', 'hse', 'facilitator']), async (req, res) => {
    try {
        const session = await Session.findById(req.params.id)
        .populate({
            path: 'training',
            select: 'title description passMark createdAt'
        })
        .populate({
            path: 'questionSet',
            populate: { path: 'questions', select: 'questionText correctAnswer createdAt' }
        })
        .populate('facilitator', 'name email role department')
        .populate('trainees', 'name email phoneNumber department role status');


        if (!session) {
            return res.status(404).json({
                success: false,
                message: 'Session not found'
            });
        }

        switch (req.user.role) {
            case 'superadmin':
            case 'hse':
            case 'hr':
                break;

            case 'facilitator':
                // if (String(session.facilitator._id) !== String(req.user._id)) {
                //     return res.status(403).json({
                //         success: false,
                //         message: 'You are not assigned to this session'
                //     });
                // }
                break;

            case 'trainee':
                return res.status(403).json({
                    success: false,
                    message: 'Trainees cannot view session details'
                });

            default:
                return res.status(403).json({
                    success: false,
                    message: 'Not authorized to view this session'
                });
        }

        return res.status(200).json({
            success: true,
            session: {
                id: session._id,
                status: session.status,
                questionSetVersion: session.questionSetVersion,
                training: {
                    id: session.training._id,
                    title: session.training.title,
                    description: session.training.description,
                    passMark: session.training.passMark,
                    createdAt: session.training.createdAt
                },
                facilitator: session.facilitator,
                trainees: session.trainees
            }
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message || 'Server error'
        });
    }
});

//Start session
app.post('/sessions/:id/start', authorize(['superadmin', 'hse', 'facilitator']), async (req, res) => {
  try {
    const { id } = req.params;

    const session = await Session.findById(id).populate('facilitator');
    if (!session) {
      return res.status(404).json({ success: false, message: 'Session not found' });
    }

    if (session.status !== 'scheduled') {
      return res.status(400).json({ 
        success: false, 
        message: `Cannot start session that is already ${session.status}` 
      });
    }

    const qrToken = crypto.randomBytes(16).toString('hex');

    session.qrCodeToken = qrToken;
    session.status = 'active';
    session.startTime = new Date();

    await session.save();

    return res.status(200).json({
      success: true,
      message: 'Session started successfully',
      session: {
        id: session._id,
        status: session.status,
        qrCodeToken: session.qrCodeToken,
        startTime: session.startTime
      }
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || 'Server error'
    });
  }
});

// End a session (facilitator only)
app.post('/sessions/:id/end', authorize(['facilitator', 'superadmin', 'hse']), async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    const session = await Session.findById(id).populate('facilitator');
    if (!session) {
      return res.status(404).json({ success: false, message: 'Session not found' });
    }
    if (req.user.role === 'facilitator' && session.facilitator._id.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Not authorized to end this session' });
    }

    if (session.status !== 'active') {
      return res.status(400).json({ 
        success: false, 
        message: `Cannot end session with status: ${session.status}` 
      });
    }

    session.status = 'completed';
    session.endTime = new Date();
    session.qrCodeToken = null; 

    await session.save();

    return res.status(200).json({
      success: true,
      message: 'Session ended successfully',
      session: {
        id: session._id,
        status: session.status,
        endTime: session.endTime
      }
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
});

// Enroll trainees into a session
app.post('/sessions/:id/enroll', authorize(['superadmin', 'hr']), async (req, res) => {
    try {
      const { id } = req.params;
      const { traineeIds } = req.body || {};

      // Validate traineeIds existence
      if (!traineeIds) {
        return res.status(400).json({
          success: false,
          message: 'Trainee ID(s) are required',
        });
      }

      // Ensure traineeIds is either a string or an array of strings
      let ids = [];
      if (typeof traineeIds === 'string') {
        ids = [traineeIds];
      } else if (Array.isArray(traineeIds) && traineeIds.every(id => typeof id === 'string')) {
        ids = traineeIds;
      } else {
        return res.status(400).json({
          success: false,
          message: 'traineeIds must be a string or an array of strings',
        });
      }

      // Find session
      const session = await Session.findById(id).populate('trainees');
      if (!session) {
        return res.status(404).json({
          success: false,
          message: 'Session not found',
        });
      }

      // Find only valid, active trainees
      const trainees = await User.find({
        _id: { $in: ids },
        role: 'trainee',
        active: true,
      });

      const validIds = trainees.map(t => t._id.toString());

      // Invalid / skipped IDs
      const skipped = ids.filter(tid => !validIds.includes(tid));

      // Prevent duplicates
      const currentIds = session.trainees.map(t => t._id.toString());
      const newIds = validIds.filter(tid => !currentIds.includes(tid));

      // Enroll new ones
      if (newIds.length > 0) {
        session.trainees.push(...newIds);
        await session.save();
      }

      return res.status(200).json({
        success: true,
        message: 'Trainee enrollment processed',
        enrolled: newIds,
        skipped,
        session: await session.populate('trainees', 'name email phoneNumber'),
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: error.message || 'Server error',
      });
    }
  }
);

// GET enrolled trainees in a session
app.get('/sessions/:id/trainees', authorize(['superadmin', 'hr', 'hse', 'facilitator']), async (req, res) => {
  try {
    const { id } = req.params;

    const session = await Session.findById(id)
      .populate('training', 'title') 
      .populate('trainees', 'name email phoneNumber department status');

    if (!session) {
      return res.status(404).json({
        success: false,
        message: 'Session not found'
      });
    }

    if (req.user.role === 'facilitator' && session.facilitator.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'You are not authorized to view trainees of this session'
      });
    }

    return res.status(200).json({
      success: true,
      session: {
        id: session._id,
        training: session.training.title,
        status: session.status,
        startTime: session.startTime,
        facilitator: session.facilitator,
        traineeCount: session.trainees.length,
        trainees: session.trainees
      }
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || 'Server error'
    });
  }
});

// Trainee scans QR, enters phone number
app.post('/sessions/:id/scan', async (req, res) => {
  try {
    const { id } = req.params;
    const { phone } = req.body; 

    const session = await Session.findOne({
      _id: id,
      status: 'active'
    }).populate('training', 'title');

    if (!session) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or inactive session'
      });
    }

    const phoneNormalized = phone.trim();
    const trainee = await User.findOne({ phoneNumber: phoneNormalized });

    if (!trainee) {
      return res.status(403).json({
        success: false,
        message: 'Trainee not found'
      });
    }

    // 3. Check enrollment
    const enrolled = session.trainees.some(
      t => t.toString() === trainee._id.toString()
    );
    if (!enrolled) {
      return res.status(403).json({
        success: false,
        message: 'You are not enrolled in this session'
      });
    }

    // 4. Grant access (✅ no ticket anymore)
    return res.status(200).json({
      success: true,
      message: 'Access granted',
      session: {
        id: session._id,
        training: session.training.title,
        facilitator: session.facilitator,
        startTime: session.startTime
      },
      trainee: {
        id: trainee._id,
        name: trainee.name,
        phone: trainee.phone
      }
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || 'Server error'
    });
  }
});

//Public endpoint for trainees joining via QR
app.get('/sessions/public/:id', async (req, res) => {
  try {
    const session = await Session.findById(req.params.id)
      .populate('training', 'title description')
      .populate('facilitator', 'name')
      .select('status startTime endTime');

    if (!session) {
      return res.status(404).json({
        success: false,
        message: 'Session not found',
      });
    }

    // Allow only active sessions to be accessible
    if (session.status !== 'active') {
      return res.status(400).json({
        success: false,
        message: 'This session is not currently active',
      });
    }

    return res.status(200).json({
      success: true,
      session: {
        id: session._id,
        trainingTitle: session.training?.title,
        description: session.training?.description,
        facilitator: session.facilitator?.name,
        status: session.status,
      },
    });
  } catch (error) {
    console.error('Error fetching public session:', error);
    return res.status(500).json({
      success: false,
      message: error.message || 'Server error',
    });
  }
});


// GET attendance for a session
app.get('/sessions/:id/attendance', authorize(['superadmin', 'hr', 'hse', 'facilitator']), async (req, res) => {
  try {
    const { id } = req.params;

    if (req.user.role === 'facilitator') {
      const facilitatorSession = await Session.findOne({ _id: id, facilitator: req.user.id });
      if (!facilitatorSession) {
        return res.status(403).json({
          success: false,
          message: 'You are not authorized to view this session attendance'
        });
      }
    }

    const attempts = await Attempt.find({ session: id })
      .populate('trainee', 'name email phoneNumber department')
      .lean();

    const attendanceMap = new Map();
    attempts.forEach(a => {
      if (!attendanceMap.has(a.trainee._id.toString())) {
        attendanceMap.set(a.trainee._id.toString(), {
          trainee: a.trainee,
          status: a.status,
          score: a.score,
          submittedAt: a.submittedAt
        });
      }
    });

    const attendanceList = Array.from(attendanceMap.values());

    return res.status(200).json({
      success: true,
      sessionId: id,
      totalPresent: attendanceList.length,
      attendance: attendanceList
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || 'Server error'
    });
  }
});

// GET questions for a session (trainee only, after QR scan validation)
app.get('/sessions/:id/questions', async (req, res) => {
  try {
    const { id } = req.params;
    const { phone } = req.query; // ✅ phone number passed as query parameter

    // 1. Validate session
    const session = await Session.findById(id)
      .populate({
        path: 'questionSet',
        populate: { path: 'questions', select: 'questionText correctAnswer' }
      })
      .populate('training', 'title')
      .lean();

    if (!session) {
      return res.status(404).json({
        success: false,
        message: 'Session not found'
      });
    }

    if (session.status !== 'active') {
      return res.status(400).json({
        success: false,
        message: 'Session is not active'
      });
    }

    // 2. Look up trainee by phone
    const trainee = await User.findOne({ phoneNumber: phone, role: 'trainee' });
    if (!trainee) {
      return res.status(403).json({
        success: false,
        message: 'Trainee not found'
      });
    }

    // 3. Check enrollment
    const enrolled = session.trainees.some(
      t => t.toString() === trainee._id.toString()
    );
    if (!enrolled) {
      return res.status(403).json({
        success: false,
        message: 'You are not enrolled in this session'
      });
    }

    // 4. Return only safe questions
    let safeQuestions = [];
    if (session.questionSet?.questions) {
      safeQuestions = session.questionSet.questions.map(q => ({
        id: q._id,
        text: q.questionText
      }));
    }

    return res.status(200).json({
      success: true,
      sessionId: id,
      trainingId: session.training._id,
      trainingName: session.training.title,
      trainee: {
        id: trainee._id,
        name: trainee.name,
        phone: trainee.phone
      },
      questions: safeQuestions
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || 'Server error'
    });
  }
});

// Submit test attempt (works with QR phone flow or logged-in trainee)
app.post('/sessions/:id/test/attempt', async (req, res) => {
  try {
    const { id: sessionId } = req.params;
    const { phone, answers } = req.body;

    // --- Step 1: Identify trainee
    let traineeId = null;
    if (req.user && req.user.role === 'trainee') {
      traineeId = req.user.id;
    } else if (phone) {
      const trainee = await User.findOne({ phoneNumber: phone, role: 'trainee' });
      if (!trainee) {
        return res.status(403).json({ success: false, message: 'Trainee not found' });
      }
      traineeId = trainee._id;
    } else {
      return res.status(401).json({ success: false, message: 'Unauthorized: Missing trainee info' });
    }

    // --- Step 2: Validate answers
    if (!answers || answers.length === 0) {
      return res.status(400).json({ success: false, message: 'Answers are required' });
    }

    const normalizeBoolean = v => {
      if (v === true || v === 1) return true;
      if (v === false || v === 0) return false;
      if (typeof v === 'string') {
        const s = v.trim().toLowerCase();
        if (['true', '1', 't'].includes(s)) return true;
        if (['false', '0', 'f'].includes(s)) return false;
      }
      return Boolean(v);
    };

    const normalizeAnswerItem = raw => {
      const qid =
        (raw.questionId || raw.id || raw.qid || raw.question || raw['question_id'] || '')
          .toString()
          .trim();

      const rawChoice = raw.chosenAnswer ?? raw.selectedAnswer ?? raw.selected ?? raw.answer ?? raw.value;
      const chosenAnswer = normalizeBoolean(rawChoice);

      return { questionId: qid, chosenAnswer };
    };

    const formattedAnswers = Array.isArray(answers)
      ? answers.map(normalizeAnswerItem)
      : [normalizeAnswerItem(answers)];

    // --- Step 3: Validate session
    const session = await Session.findById(sessionId)
      .populate({
        path: 'questionSet',
        populate: { path: 'questions', select: '_id questionText correctAnswer' }
      })
      .populate('training', 'passMark')
      .lean();

    if (!session) return res.status(404).json({ success: false, message: 'Session not found' });
    if (session.status !== 'active') return res.status(400).json({ success: false, message: 'Session is not active' });

    const questions = (session.questionSet?.questions) || [];
    const totalQuestions = questions.length;

    const correctMap = {};
    questions.forEach(q => {
      correctMap[q._id.toString()] = normalizeBoolean(q.correctAnswer);
    });

    // --- Step 4: Calculate score
    let score = 0;
    const evaluated = formattedAnswers.map(a => {
      const correct = correctMap[a.questionId];
      const isCorrect = a.chosenAnswer === correct;
      if (isCorrect) score++;
      return { question: a.questionId, selectedAnswer: a.chosenAnswer, isCorrect };
    });

    const passMark = session.training?.passMark ?? Math.ceil(totalQuestions * 0.7);
    const status = score >= passMark ? 'passed' : 'failed';

    // --- Step 5: Record attempt
    const lastAttempt = await Attempt.findOne({ trainee: traineeId, session: sessionId })
      .sort({ attemptNumber: -1 })
      .lean();
    const attemptNumber = lastAttempt ? (lastAttempt.attemptNumber || 0) + 1 : 1;

    const attemptDoc = new Attempt({
      trainee: traineeId,
      session: sessionId,
      answers: evaluated,
      score,
      totalQuestions,
      status,
      attemptNumber
    });

    await attemptDoc.save();

    return res.status(201).json({
      success: true,
      message: 'Attempt submitted successfully',
      attempt: {
        id: attemptDoc._id,
        trainee: traineeId,
        session: sessionId,
        score,
        totalQuestions,
        status,
        attemptNumber,
        submittedAt: attemptDoc.submittedAt
      }
    });
  } catch (err) {
    console.error('attempt submit error:', err);
    return res.status(500).json({ success: false, message: err.message || 'Server error' });
  }
});


// GET session results
app.get('/sessions/:id/results', authorize(['HR', 'facilitator', 'superadmin']), async (req, res) => {
  try {
    const { id } = req.params;

    const attempts = await Attempt.find({ session: id })
      .populate('trainee', 'name email') 
      .sort({ submittedAt: 1 });

    if (!attempts || attempts.length === 0) {
      return res.status(404).json({ success: false, message: 'No attempts found for this session' });
    }

    const totalTrainees = attempts.length;
    const passed = attempts.filter(a => a.status === 'passed').length;
    const failed = attempts.filter(a => a.status === 'failed').length;


    res.json({
      success: true,
      summary: {
        totalTrainees,
        passed,
        failed
      },
      attempts 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: err });
  }
});

// GET /sessions/:id/attempts
// GET /sessions/:id/attempts
app.get('/sessions/:id/attempts', authorize(['hr', 'facilitator', 'superadmin']), async (req, res) => {
  try {
    const { id } = req.params;

    // Fetch session and populate facilitator
    const session = await Session.findById(id).populate('facilitator', 'name email role _id');
    if (!session) {
      return res.status(404).json({
        success: false,
        message: 'Session not found'
      });
    }

    // 🧩 Log to confirm identities
    console.log('🧩 Facilitator access check:\n', {
      sessionId: id,
      loggedInUser: req.user,
      sessionFacilitatorId: session.facilitator?._id?.toString()
    });

    // ✅ Facilitator access restriction
    if (req.user.role === 'facilitator') {
      if (session.facilitator && session.facilitator._id && session.facilitator._id.toString() !== req.user.id.toString()) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to view attempts for this session'
        });
      }
    }

    // Fetch attempts
    const attempts = await Attempt.find({ session: id })
      .populate('trainee', 'name phone email department role')
      .sort({ submittedAt: -1 });

    // Handle no attempts
    if (!attempts || attempts.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'No attempts found for this session'
      });
    }

    // ✅ Successful response
    res.json({
      success: true,
      session: {
        id: session._id,
        training: session.training,
        facilitator: session.facilitator
      },
      count: attempts.length,
      attempts
    });

  } catch (err) {
    console.error('🔥 Error in /sessions/:id/attempts:', err);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: err.message
    });
  }
});





// GET /trainees/:traineeId/history
app.get('/trainees/:traineeId/history', authorize(['superadmin', 'hr', 'hse', 'facilitator', 'trainee']), async (req, res) => {
  try {
    const { traineeId } = req.params;

    const trainee = await User.findById(traineeId).select('name phone email department role');
    if (!trainee || trainee.role !== 'trainee') {
      return res.status(404).json({
        success: false,
        message: 'Trainee not found'
      });
    }

    let query = { trainee: traineeId };

    if (req.user.role === 'trainee') {
      if (req.user._id.toString() !== traineeId) {
        return res.status(403).json({
          success: false,
          message: 'Trainees can only view their own history'
        });
      }
    }

    if (req.user.role === 'facilitator') {
     
      const facilitatorSessions = await Session.find({ facilitator: req.user._id })
        .select('_id');

      const sessionIds = facilitatorSessions.map(s => s._id);

      if (sessionIds.length === 0) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to view this trainee’s history'
        });
      }

      query.session = { $in: sessionIds };
    }

    
    const attempts = await Attempt.find(query)
      .populate('session', 'training facilitator status startTime endTime')
      .populate({
        path: 'session',
        populate: { path: 'training', select: 'title description passMark' }
      })
      .populate({
        path: 'session',
        populate: { path: 'facilitator', select: 'name email phone' }
      })
      .sort({ submittedAt: -1 });

    if (!attempts.length) {
      return res.status(404).json({
        success: false,
        message: 'No attempts found for this trainee'
      });
    }

    res.json({
      success: true,
      trainee,
      count: attempts.length,
      attempts
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

//reports 
app.get('/reports/attempts', authorize(['superadmin', 'hr']), async (req, res) => {
  try {
    let { startDate, endDate } = req.query;

    // Default to last 30 days if not provided
    if (!startDate || !endDate) {
      const end = new Date();
      const start = new Date();
      start.setDate(end.getDate() - 30);
      startDate = start.toISOString();
      endDate = end.toISOString();
    }

    const start = new Date(startDate);
    const end = new Date(endDate);

    // Fetch attempts in the range
    const attempts = await Attempt.find({
      submittedAt: { $gte: start, $lte: end }
    })
      .populate("trainee", "name phone email department role")
      .populate("session", "training facilitator")
      .lean();

    if (!attempts.length) {
      return res.status(200).json({
        success: false,
        message: "No attempts found in this time range"
      });
    }

    // ---------- BASIC AGGREGATES ----------
    const scores = attempts.map(a => a.score || 0);
    const totalAttempts = scores.length;
    const averageScore = scores.reduce((a, b) => a + b, 0) / totalAttempts;
    const passed = attempts.filter(a => a.passed).length;
    const failed = totalAttempts - passed;

    // ---------- DISTRIBUTION ----------
    const minScore = Math.min(...scores);
    const maxScore = Math.max(...scores);
    const medianScore = scores.sort((a, b) => a - b)[Math.floor(totalAttempts / 2)];
    const modeScore = scores.sort((a, b) =>
      scores.filter(v => v === a).length - scores.filter(v => v === b).length
    ).pop();

    const buckets = {
      "0-2": scores.filter(s => s <= 2).length,
      "3-4": scores.filter(s => s >= 3 && s <= 4).length,
      "5-6": scores.filter(s => s >= 5 && s <= 6).length,
      "7-8": scores.filter(s => s >= 7 && s <= 8).length,
      "9-10": scores.filter(s => s >= 9).length,
    };

    // ---------- TIME ANALYSIS ----------
    const durations = attempts
      .map(a => (a.startedAt && a.submittedAt)
        ? (new Date(a.submittedAt) - new Date(a.startedAt)) / 60000
        : null)
      .filter(Boolean);

    const avgDuration = durations.length
      ? (durations.reduce((a, b) => a + b, 0) / durations.length)
      : null;

    // Attempts per day
    const attemptsPerDay = {};
    attempts.forEach(a => {
      const day = new Date(a.submittedAt).toISOString().split("T")[0];
      attemptsPerDay[day] = (attemptsPerDay[day] || 0) + 1;
    });

    // ---------- DEPARTMENT BREAKDOWN ----------
    const departmentStats = {};
    attempts.forEach(a => {
      const dept = a.trainee?.department || "Unknown";
      if (!departmentStats[dept]) {
        departmentStats[dept] = { total: 0, passed: 0, scores: [] };
      }
      departmentStats[dept].total++;
      departmentStats[dept].scores.push(a.score || 0);
      if (a.passed) departmentStats[dept].passed++;
    });

    Object.keys(departmentStats).forEach(d => {
      const dept = departmentStats[d];
      dept.averageScore = dept.scores.reduce((a, b) => a + b, 0) / dept.total;
      dept.passRate = (dept.passed / dept.total) * 100;
      delete dept.scores;
    });

    // ---------- TOP & BOTTOM PERFORMERS ----------
    const sortedAttempts = [...attempts].sort((a, b) => b.score - a.score);
    const topPerformers = sortedAttempts.slice(0, 5).map(a => ({
      name: a.trainee?.name,
      score: a.score,
      department: a.trainee?.department
    }));
    const bottomPerformers = sortedAttempts.slice(-5).map(a => ({
      name: a.trainee?.name,
      score: a.score,
      department: a.trainee?.department
    }));

    // ---------- NEW: FREQUENT FAILURES ----------
    const failCountMap = {};
    attempts.forEach(a => {
      const name = a.trainee?.name || "Unknown";
      if (!a.passed) failCountMap[name] = (failCountMap[name] || 0) + 1;
    });

    const frequentFails = Object.entries(failCountMap)
      .filter(([_, count]) => count >= 3)
      .map(([name, count]) => ({ traineeName: name, failCount: count }));

    // ---------- NEW: WEEKLY STATS ----------
    const weeklyStats = [];
    const weekMap = {};

    attempts.forEach(a => {
      const date = new Date(a.submittedAt);
      const year = date.getFullYear();
      const week = Math.ceil((((date - new Date(year, 0, 1)) / 86400000) + new Date(year, 0, 1).getDay() + 1) / 7);
      const key = `${year}-W${week}`;

      if (!weekMap[key]) {
        weekMap[key] = { totalAttempts: 0, passed: 0 };
      }
      weekMap[key].totalAttempts++;
      if (a.passed) weekMap[key].passed++;
    });

    Object.entries(weekMap).forEach(([week, data]) => {
      weeklyStats.push({
        week,
        totalAttempts: data.totalAttempts,
        passRate: +(data.passed / data.totalAttempts * 100).toFixed(1),
        newUsers: Math.floor(Math.random() * 10) + 1 // Mock; replace with actual user count if tracked
      });
    });

    // ---------- RESPONSE ----------
    res.json({
      success: true,
      timeSpan: { startDate, endDate },
      overview: {
        totalAttempts,
        averageScore: +averageScore.toFixed(2),
        passRate: ((passed / totalAttempts) * 100).toFixed(1),
        failRate: ((failed / totalAttempts) * 100).toFixed(1)
      },
      scoreDistribution: {
        min: minScore,
        max: maxScore,
        median: medianScore,
        mode: modeScore,
        buckets
      },
      timeAnalysis: {
        averageDurationMinutes: avgDuration ? avgDuration.toFixed(1) : null,
        fastestAttemptMinutes: durations.length ? Math.min(...durations).toFixed(1) : null,
        slowestAttemptMinutes: durations.length ? Math.max(...durations).toFixed(1) : null,
        attemptsPerDay
      },
      departmentBreakdown: departmentStats,
      topPerformers,
      bottomPerformers,
      weeklyStats,      // 📊 added
      frequentFails     // ⚠️ added
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error", error: err.message });
  }

});

// -------------------- FETCH ALL SESSIONS (Superadmin view) --------------------
app.get("/sessions", authorize(["superadmin", "hr", "hse", "facilitator"]), async (req, res) => {
  try {
    const filter = req.user.role === "facilitator" ? { facilitator: req.user.id } : {};
    const sessions = await Session.find(filter)
      .populate("training", "title")
      .populate("facilitator", "name email")
      .populate("trainees", "name")
      .lean();

    const formatted = sessions.map((s) => ({
      id: s._id,
      trainingTitle: s.training?.title,
      facilitator: s.facilitator?.name,
      traineeCount: s.trainees?.length || 0,
      status: s.status,
      createdAt: s.createdAt,
    }));

    return res.status(200).json({
      success: true,
      count: formatted.length,
      sessions: formatted,
    });
  } catch (error) {
    console.error("Error fetching sessions:", error);
    res.status(500).json({
      success: false,
      message: error.message || "Failed to load sessions.",
    });
  }
});

// ✅ GET a specific Question Set by ID
app.get('/questionsets/:id', authorize(['superadmin', 'hr', 'hse', 'facilitator']), async (req, res) => {
    try {
        const { id } = req.params;

        const questionSet = await QuestionSet.findById(id)
            .populate('questions') // if you store questions in a sub-schema or reference
            .lean();

        if (!questionSet) {
            return res.status(404).json({
                success: false,
                message: 'Question set not found'
            });
        }

        return res.status(200).json({
            success: true,
            questionSet
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message || 'Server error'
        });
    }
});

// ✅ GET trainee's attempts for a specific session (public, phone-based)
app.get('/sessions/:id/trainee-attempts', async (req, res) => {
  try {
    const { id } = req.params;
    const { phone } = req.query;

    if (!phone) {
      return res.status(400).json({
        success: false,
        message: 'Phone number is required'
      });
    }

    // 1. Find trainee by phone
    const trainee = await User.findOne({ 
      phoneNumber: phone, 
      role: 'trainee' 
    }).select('_id name phone email');

    if (!trainee) {
      return res.status(404).json({
        success: false,
        message: 'Trainee not found'
      });
    }

    // 2. Validate session exists and is active
    const session = await Session.findById(id)
      .select('status trainees')
      .lean();

    if (!session) {
      return res.status(404).json({
        success: false,
        message: 'Session not found'
      });
    }

    // 3. Check if trainee is enrolled
    const isEnrolled = session.trainees.some(
      t => t.toString() === trainee._id.toString()
    );

    if (!isEnrolled) {
      return res.status(403).json({
        success: false,
        message: 'You are not enrolled in this session'
      });
    }

    // 4. Fetch all attempts for this trainee in this session
    const attempts = await Attempt.find({
      trainee: trainee._id,
      session: id
    })
      .select('score totalQuestions status attemptNumber submittedAt')
      .sort({ attemptNumber: -1 })
      .lean();

    // 5. Determine current status
    let currentStatus = 'new';
    let latestAttempt = null;

    if (attempts.length > 0) {
      latestAttempt = attempts[0]; // Most recent attempt
      currentStatus = latestAttempt.status; // 'passed' or 'failed'
    }

    return res.status(200).json({
      success: true,
      trainee: {
        id: trainee._id,
        name: trainee.name,
        phone: trainee.phone
      },
      currentStatus,
      latestAttempt,
      totalAttempts: attempts.length,
      allAttempts: attempts
    });

  } catch (error) {
    console.error('Error fetching trainee attempts:', error);
    return res.status(500).json({
      success: false,
      message: error.message || 'Server error'
    });
  }
});

// ENDPOINT: Get User Profile with Stats
app.get('/profile/stats', authorize(), async (req, res) => {
  try {
    const userId = req.user.id;

    // Fetch user details
    const user = await User.findById(userId).select('-password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    let stats = {};

    // ✅ TRAINEE STATS
    if (user.role === 'trainee') {
      // Get all attempts by this trainee
      const attempts = await Attempt.find({ trainee: userId })
        .populate('session', 'training startTime endTime')
        .populate({
          path: 'session',
          populate: { path: 'training', select: 'title passMark' }
        })
        .sort({ submittedAt: -1 });

      const totalAttempts = attempts.length;
      const passedAttempts = attempts.filter(a => a.status === 'passed').length;
      const failedAttempts = attempts.filter(a => a.status === 'failed').length;

      // Calculate average score
      const scores = attempts.map(a => a.score || 0);
      const averageScore = totalAttempts > 0 
        ? (scores.reduce((a, b) => a + b, 0) / totalAttempts).toFixed(2)
        : 0;

      // Get best and worst scores
      const bestScore = totalAttempts > 0 ? Math.max(...scores) : 0;
      const worstScore = totalAttempts > 0 ? Math.min(...scores) : 0;

      // Get trainings completed
      const trainingsSet = new Set();
      attempts.forEach(a => {
        if (a.session?.training?._id) {
          trainingsSet.add(a.session.training._id.toString());
        }
      });

      // Sessions enrolled in
      const sessions = await Session.find({ trainees: userId })
        .populate('training', 'title')
        .lean();

      stats = {
        totalAttempts,
        passedAttempts,
        failedAttempts,
        passRate: totalAttempts > 0 ? ((passedAttempts / totalAttempts) * 100).toFixed(1) : 0,
        averageScore,
        bestScore,
        worstScore,
        trainingsCompleted: trainingsSet.size,
        sessionsEnrolled: sessions.length,
        recentAttempts: attempts.slice(0, 5).map(a => ({
          id: a._id,
          training: a.session?.training?.title || 'Unknown',
          score: a.score,
          totalQuestions: a.totalQuestions,
          status: a.status,
          attemptNumber: a.attemptNumber,
          submittedAt: a.submittedAt
        }))
      };
    }

    // ✅ FACILITATOR STATS
    else if (user.role === 'facilitator') {
      // Get sessions facilitated
      const sessions = await Session.find({ facilitator: userId })
        .populate('training', 'title')
        .populate('trainees', '_id')
        .lean();

      // Get all attempts from sessions facilitated
      const sessionIds = sessions.map(s => s._id);
      const attempts = await Attempt.find({ session: { $in: sessionIds } })
        .lean();

      const totalTrainees = new Set(attempts.map(a => a.trainee.toString())).size;
      const totalSessions = sessions.length;
      const completedSessions = sessions.filter(s => s.status === 'completed').length;
      const activeSessions = sessions.filter(s => s.status === 'active').length;

      const passedAttempts = attempts.filter(a => a.status === 'passed').length;
      const totalAttempts = attempts.length;
      const averagePassRate = totalAttempts > 0 
        ? ((passedAttempts / totalAttempts) * 100).toFixed(1)
        : 0;

      stats = {
        totalSessions,
        completedSessions,
        activeSessions,
        totalTraineesTaught: totalTrainees,
        totalAttempts,
        averagePassRate,
        recentSessions: sessions
          .sort((a, b) => new Date(b.startTime) - new Date(a.startTime))
          .slice(0, 5)
          .map(s => ({
            id: s._id,
            training: s.training?.title || 'Unknown',
            traineeCount: s.trainees?.length || 0,
            status: s.status,
            startTime: s.startTime,
            endTime: s.endTime
          }))
      };
    }

    // ✅ STAFF STATS (HR, HSE, etc.)
    else if (['hr', 'hse', 'superadmin'].includes(user.role)) {
      // User count by role
      const userStats = await User.aggregate([
        {
          $group: {
            _id: '$role',
            count: { $sum: 1 }
          }
        }
      ]);

      const usersByRole = {};
      userStats.forEach(stat => {
        usersByRole[stat._id] = stat.count;
      });

      // Total trainings
      const totalTrainings = await Training.countDocuments();

      // Total sessions
      const totalSessions = await Session.countDocuments();

      // Total attempts
      const totalAttempts = await Attempt.countDocuments();

      stats = {
        usersByRole,
        totalTrainings,
        totalSessions,
        totalAttempts,
        systemStats: {
          totalUsers: await User.countDocuments(),
          totalTrainees: await User.countDocuments({ role: 'trainee' }),
          totalFacilitators: await User.countDocuments({ role: 'facilitator' }),
          activeSessions: await Session.countDocuments({ status: 'active' })
        }
      };
    }

    return res.status(200).json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phoneNumber: user.phoneNumber,
        department: user.department,
        role: user.role,
        status: user.status,
        createdAt: user.createdAt
      },
      stats
    });

  } catch (error) {
    console.error('Profile stats error:', error);
    return res.status(500).json({
      success: false,
      message: error.message || 'Server error'
    });
  }
});

// User edits their own profile
app.put('/me/edit', authorize(), async (req, res) => {
  try {
    // Enforce JSON only
    if (!req.is('application/json')) {
      return res.status(415).json({
        success: false,
        message: 'Content-Type must be application/json'
      });
    }

    const userId = req.user.id;
    const { name, email, phoneNumber, department, password } = req.body || {};

    // Fetch the current user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Build update data based on user role
    const updateData = {};

    // All users can update their name
    if (name) {
      updateData.name = name;
    }

    // Staff (non-trainees) can update email
    if (email && user.role !== 'trainee') {
      // Check if email already exists for another user
      const existingEmail = await User.findOne({ 
        email, 
        _id: { $ne: userId } 
      });
      if (existingEmail) {
        return res.status(409).json({
          success: false,
          message: 'Email is already in use'
        });
      }
      updateData.email = email;
    }

    // Trainees can update phone number and department
    if (user.role === 'trainee') {
      if (phoneNumber) {
        // Check if phone already exists for another user
        const existingPhone = await User.findOne({ 
          phoneNumber, 
          _id: { $ne: userId } 
        });
        if (existingPhone) {
          return res.status(409).json({
            success: false,
            message: 'Phone number is already in use'
          });
        }
        updateData.phoneNumber = phoneNumber;
      }
      if (department) {
        updateData.department = department;
      }
    }

    // Any user can update their password
    if (password) {
      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message: 'Password must be at least 6 characters'
        });
      }
      updateData.password = await bcrypt.hash(password, 10);
    }

    // If no valid updates provided
    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No valid fields to update'
      });
    }

    // Update the user
    const updatedUser = await User.findByIdAndUpdate(userId, updateData, { new: true })
      .select('-password');

    return res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      user: updatedUser
    });

  } catch (error) {
    if (error.code === 11000) {
      const duplicateField = Object.keys(error.keyPattern || {})[0];
      return res.status(409).json({
        success: false,
        message: `${duplicateField} is already in use`
      });
    }

    return res.status(500).json({
      success: false,
      message: error.message || 'Server error'
    });
  }
});

//Admin edits any user's info
app.put('/admin/users/:id/edit', authorize(['superadmin', 'hr', 'hse']), async (req, res) => {
  try {
    // Enforce JSON only
    if (!req.is('application/json')) {
      return res.status(415).json({
        success: false,
        message: 'Content-Type must be application/json'
      });
    }

    const targetUserId = req.params.id;
    const { name, email, phoneNumber, department, role, status, password } = req.body || {};

    // Fetch target user
    const targetUser = await User.findById(targetUserId);
    if (!targetUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // ✅ Role-based permission checks
    if (req.user.role === 'hr') {
      // HR can only edit trainees and HSE
      if (!['trainee', 'hse'].includes(targetUser.role)) {
        return res.status(403).json({
          success: false,
          message: 'HR can only edit trainee and HSE accounts'
        });
      }
    } else if (req.user.role === 'hse') {
      // HSE can only edit facilitators
      if (targetUser.role !== 'facilitator') {
        return res.status(403).json({
          success: false,
          message: 'HSE can only edit facilitator accounts'
        });
      }
    }
    // Superadmin can edit anyone

    // Prevent self-deletion of superadmin role (optional safety check)
    if (req.user.role !== 'superadmin' && role === 'superadmin') {
      return res.status(403).json({
        success: false,
        message: 'Only superadmin can create superadmin accounts'
      });
    }

    const updateData = {};

    // Update name
    if (name) {
      updateData.name = name;
    }

    // Update email (for non-trainees)
    if (email && targetUser.role !== 'trainee') {
      const existingEmail = await User.findOne({ 
        email, 
        _id: { $ne: targetUserId } 
      });
      if (existingEmail) {
        return res.status(409).json({
          success: false,
          message: 'Email is already in use'
        });
      }
      updateData.email = email;
    }

    // Update phone number (for trainees)
    if (phoneNumber && targetUser.role === 'trainee') {
      const existingPhone = await User.findOne({ 
        phoneNumber, 
        _id: { $ne: targetUserId } 
      });
      if (existingPhone) {
        return res.status(409).json({
          success: false,
          message: 'Phone number is already in use'
        });
      }
      updateData.phoneNumber = phoneNumber;
    }

    // Update department (for trainees)
    if (department && targetUser.role === 'trainee') {
      updateData.department = department;
    }

    // Update role (with permission checks)
    if (role) {
      if (req.user.role === 'hr' && !['trainee', 'hse'].includes(role)) {
        return res.status(403).json({
          success: false,
          message: 'HR can only set role to trainee or hse'
        });
      }
      if (req.user.role === 'hse' && role !== 'facilitator') {
        return res.status(403).json({
          success: false,
          message: 'HSE can only set role to facilitator'
        });
      }
      updateData.role = role;
    }

    // Update status (active/inactive)
    if (typeof status !== 'undefined') {
      if (!['active', 'inactive'].includes(status)) {
        return res.status(400).json({
          success: false,
          message: 'Status must be either "active" or "inactive"'
        });
      }
      updateData.status = status;
    }

    // Update password
    if (password) {
      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message: 'Password must be at least 6 characters'
        });
      }
      updateData.password = await bcrypt.hash(password, 10);
    }

    // If no valid updates provided
    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No valid fields to update'
      });
    }

    // Perform update
    const updatedUser = await User.findByIdAndUpdate(targetUserId, updateData, { new: true })
      .select('-password');

    return res.status(200).json({
      success: true,
      message: 'User updated successfully by admin',
      user: updatedUser
    });

  } catch (error) {
    if (error.code === 11000) {
      const duplicateField = Object.keys(error.keyPattern || {})[0];
      return res.status(409).json({
        success: false,
        message: `${duplicateField} is already in use`
      });
    }

    return res.status(500).json({
      success: false,
      message: error.message || 'Server error'
    });
  }
});