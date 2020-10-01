const User = require('../models/User');
const shortId = require('shortid');
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt');

exports.signup = (req, res) => {
  const { name, email, password } = req.body;
  User.findOne({ email }).exec((err, user) => {
    if (user) {
      return res.status(400).json({
        error: 'Email is already taken',
      });
    }

    let username = shortId.generate();
    let profile = `${process.env.CLIENT_URL}/profile/${username}`;

    let newUser = new User({ name, email, password, profile, username });
    newUser.save((err, success) => {
      if (err) {
        return res.status(400).json({
          error: err,
        });
      }

      res.status(200).json({
        message: 'Signup success! please sign in.',
      });
    });
  });
};

exports.signin = (req, res) => {
  const { email, password } = req.body;
  // check if user exist
  User.findOne({ email }).exec((err, user) => {
    if (err || !user) {
      res.status(400).json({
        error: 'User with that email does not exist',
      });
    }
    // authenticate
    if (!user.authenticate(password)) {
      res.status(400).json({
        error: 'Email and password do not match',
      });
    }
    // generate a token and send to the client
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.cookie('token', token, { expiresIn: '1d' });
    const { _id, username, name, role } = user;

    return res.json({
      token,
      user: { _id, username, name, role },
    });
  });
};

exports.signout = (req, res) => {
  res.clearCookie('token');
  res.status(200).json({
    message: 'signout success!',
  });
};

exports.requireSignin = expressJwt({
  secret: process.env.JWT_SECRET,
  algorithms: ['HS256'], // added later
  userProperty: 'auth',
});
