const express = require('express');
const router = express.Router();
const User = require('../models/user');
const passport = require('passport');
const config = require('../config/database')
const jwt = require('jsonwebtoken');

// Register
router.post('/register', (req, res, next) => {
  let newUser = new User({
    name: req.body.name,
    email: req.body.email,
    username: req.body.username,
    password: req.body.password
  });

  User.addUser(newUser, (err, user) => {
    if(err) {
      res.json({success: false, msg: 'Failed to register user', error: err});
    }
    else {
      res.json({success: true, msg: 'User registered!'})
    }
  });
});

// Authenticate
router.post('/authenticate', (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;

  User.getUserByUsername(username, (err, user) => {
    if(err) throw err;

    if(!user) {
      return res.json({success: false, msg: 'Username or Password is not Correct'})
    }

    User.comparePassword(password, user.password, (err, isMatch) => {
      if(err) throw err;

      if (isMatch) {
        const token = jwt.sign(user, config.secret, {
          expiresIn: 600 // 10 minutes
        })

        res.json({
          success: true,
          token: 'JWT ' + token,
          user: {
            id: user._id,
            name: user.name,
            username: user.username,
            email: user.email
          }
        })
      }

      else {
        return res.json({success: false, msg: 'Username or Password is not Correct'})
      }

    })

  })
});

// Profile
router.get('/profile', passport.authenticate('jwt', {session:false}), (req, res, next) => {
  res.json({user: req.user});
});

module.exports = router;
