require('dotenv').config();
const express = require('express');
const router = express.Router();
const app = express();
const connectDB = require('./db');
const authorize = require('./auth/auth');
const cors = require('cors');
const path = require('path');
const apiControllers = require('./controllers/apiControllers');

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
app.post('/login', apiControllers.login);

//Trainee login via phone after scanning QR
app.post('/sessions/:id/login', apiControllers.traineeLogin);

//create user
app.post('/user-add', authorize(['superadmin', 'hr']), apiControllers.addUser);

//list all users
app.get('/users', authorize(['superadmin', 'hr', 'hse', 'facilitator']), apiControllers.getUsers);

// UPDATE user info
app.put('/users/:id', authorize(['superadmin', 'hr', 'hse']), apiControllers.updateUser);

// TOGGLE trainee's status 
app.patch('/users/:id/status', authorize(['superadmin', 'hr']), apiControllers.toggleUserStatus);

// GET logged-in user's profile
app.get('/me', authorize(), apiControllers.getMe);

// DELETE a user
app.delete('/users/:id', authorize(['superadmin', 'hr', 'hse']), apiControllers.deleteUser);

// GET a single user by ID
app.get('/users/:id', authorize(['superadmin', 'hr', 'hse', 'facilitator']), apiControllers.getUserById);

// CREATE a training  
app.post('/trainings', authorize(['superadmin', 'hse']), apiControllers.createTraining);

// LIST trainings (role-specific visibility)
app.get('/trainings', authorize(['superadmin', 'hr', 'hse', 'facilitator']), apiControllers.getTrainings);

// GET a specific training by ID
app.get('/trainings/:id', authorize(['superadmin', 'hr', 'hse', 'facilitator']), apiControllers.getTrainingById);

// UPDATE a training
app.put('/trainings/:id', authorize(['superadmin', 'hse']), apiControllers.updateTraining);

// DELETE a training
app.delete('/trainings/:id', authorize(['superadmin', 'hse']), apiControllers.deleteTraining);

// ADD questions to a training
app.post('/trainings/:id/questions', authorize(['superadmin', 'hse']), apiControllers.addQuestionsToTraining);

// CREATE a training session
app.post('/sessions', authorize(['superadmin', 'hr', 'hse']), apiControllers.createSession);

// GET a specific session with full details
app.get('/sessions/:id', authorize(['superadmin', 'hr', 'hse', 'facilitator']), apiControllers.getSessionById);

//Start session
app.post('/sessions/:id/start', authorize(['superadmin', 'hse', 'facilitator']), apiControllers.startSession);

// End a session (facilitator only)
app.post('/sessions/:id/end', authorize(['facilitator', 'superadmin', 'hse']), apiControllers.endSession);

// Enroll trainees into a session
app.post('/sessions/:id/enroll', authorize(['superadmin', 'hr']), apiControllers.enrollTrainees);

// GET enrolled trainees in a session
app.get('/sessions/:id/trainees', authorize(['superadmin', 'hr', 'hse', 'facilitator']), apiControllers.getSessionTrainees);

// Trainee scans QR, enters phone number
app.post('/sessions/:id/scan', apiControllers.scanSession);

//Public endpoint for trainees joining via QR
app.get('/sessions/public/:id', apiControllers.getPublicSession);

// GET attendance for a session
app.get('/sessions/:id/attendance', authorize(['superadmin', 'hr', 'hse', 'facilitator']), apiControllers.getSessionAttendance);

// GET questions for a session (trainee only, after QR scan validation)
app.get('/sessions/:id/questions', apiControllers.getSessionQuestions);

// Submit test attempt (works with QR phone flow or logged-in trainee)
app.post('/sessions/:id/test/attempt', apiControllers.submitTestAttempt);

// GET session results
app.get('/sessions/:id/results', authorize(['HR', 'facilitator', 'superadmin']), apiControllers.getSessionResults);

// GET /sessions/:id/attempts
app.get('/sessions/:id/attempts', authorize(['hr', 'facilitator', 'superadmin']), apiControllers.getSessionAttempts);

// GET /trainees/:traineeId/history
app.get('/trainees/:traineeId/history', authorize(['superadmin', 'hr', 'hse', 'facilitator', 'trainee']), apiControllers.getTraineeHistory);

//reports 
app.get('/reports/attempts', authorize(['superadmin', 'hr']), apiControllers.getAttemptsReport);

// -------------------- FETCH ALL SESSIONS (Superadmin view) --------------------
app.get("/sessions", authorize(["superadmin", "hr", "hse", "facilitator"]), apiControllers.getAllSessions);

// ✅ GET a specific Question Set by ID
app.get('/questionsets/:id', authorize(['superadmin', 'hr', 'hse', 'facilitator']), apiControllers.getQuestionSetById);

// ✅ GET trainee's attempts for a specific session (public, phone-based)
app.get('/sessions/:id/trainee-attempts', apiControllers.getTraineeAttempts);

// ENDPOINT: Get User Profile with Stats
app.get('/profile/stats', authorize(), apiControllers.getProfileStats);

// User edits their own profile
app.put('/me/edit', authorize(), apiControllers.editMyProfile);

//Admin edits any user's info
app.put('/admin/users/:id/edit', authorize(['superadmin', 'hr', 'hse']), apiControllers.adminEditUser);
