require('dotenv').config();
const express = require('express');
const app = express();
const mongoose = require('mongoose');
const connectDB = require('./db');
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


const apiRoutes = require('./routes/apiRoutes');
app.use('/', apiRoutes);

module.exports = app;
