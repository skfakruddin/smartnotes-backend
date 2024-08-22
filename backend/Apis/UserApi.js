const exp = require('express');
const userApp = exp.Router();
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const expressAsyncHandler = require('express-async-handler');
const tokenVerify = require('../middlewares/tokenVerify');

userApp.use(exp.json());

// Get all users
userApp.get('/users', tokenVerify, expressAsyncHandler(async (req, res) => {
    const usersCollection = req.app.get('usersCollection');
    let users = await usersCollection.find().toArray();
    res.send({ message: "All Users", payload: users });
}));

// Register a new user
userApp.post('/users', expressAsyncHandler(async (req, res) => {
    const usersCollection = req.app.get('usersCollection');
    let newUser = req.body;
    let existingUser = await usersCollection.findOne({ username: newUser.username });

    if (existingUser) {
        return res.send({ message: "User Already Exists" });
    }

    // Hash the user password and notes password
    newUser.password = await bcrypt.hash(newUser.password, 9);
    // newUser.notesPassword = await bcrypt.hash(newUser.notesPassword, 9); // Hash the notes password

    await usersCollection.insertOne(newUser);
    res.send({ message: "User Created", payload: newUser });
}));

// User login
userApp.post('/users/login', expressAsyncHandler(async (req, res) => {
    const usersCollection = req.app.get('usersCollection');
    let user = await usersCollection.findOne({ username: req.body.username });

    if (!user) {
        return res.send({ message: "Invalid Username" });
    }

    let isPasswordCorrect = await bcrypt.compare(req.body.password, user.password);

    if (!isPasswordCorrect) {
        return res.send({ message: "Invalid Password" });
    }

    let token = jwt.sign({ username: user.username }, process.env.SECRET, { expiresIn: '2h' });
    res.send({ message: "Login Success", token, user });
}));

module.exports = userApp;
