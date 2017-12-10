const express = require('express');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken');
const config = require('../config/database');
const User = require('../models/user');

//  Register
router.post('/register', (req, res, next) => {

    let newUser = new User({
        name: req.body.name,
        email: req.body.email,
        username: req.body.username,
        password: req.body.password
    });

    User.addUser(newUser, (err, user) => {
        if(err) {
            res.json({success: false, msg: 'Failed to register user'});
        } else {
            res.json({success: true, msg: 'User registered'});
        }
    });
});

//  Authenticate
router.post('/authenticate', (req, res, next) => {
    const username = req.body.username;
    const password = req.body.password;

    //  Is the given username found in the database?
    User.getUserByUsername(username, (err, user) => {
        if(err) throw err;
        if(!user) {
            return res.json({success: false, msg: 'User not found'});
        }

        //  Does the given password match with the password of the found user?
        User.comparePassword(password, user.password, (err, isMatch) => {
            if(err) throw err;

            //  Create token.
            if(isMatch) {
                const token = jwt.sign({data: user}, config.secret, {
                    expiresIn: 604800 // 1 week
                });
                
                //  Respond: success, token, user as an object w/o the password.
                res.json({
                    success: true,
                    token: 'JWT '+token,
                    user: {
                        id: user._id,
                        name: user.name,
                        username: user.username,
                        email: user.email
                    }
                });
            } else {
                //  Respond: NOTSuccess, message.
                return res.json({success: false, msg: 'Wrong password'});
            }
        });
    });
});

//  Profile
router.get('/profile', passport.authenticate('jwt', {session: false}),(req, res, next) => {
    res.json({user: req.user});
});


module.exports = router;