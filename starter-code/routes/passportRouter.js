const express = require('express');
const passportRouter = express.Router();
const bcrypt = require('bcrypt');
const User = require('../models/user');
const passport = require('passport');
const zxcvbn = require('zxcvbn');

passportRouter.get('/signup', (req, res) => {
    res.render('passport/signup.hbs');
});

passportRouter.post('/signup', (req, res) => {
    const { username, password } = req.body;
    const salt = bcrypt.genSaltSync();
    const hashPassword = bcrypt.hashSync(password, salt);
    if (username === '' || password === '') {
        res.render('passport/signup', {
            errorMessage: 'You need a username and a password to register'
        });
        return;
    }
    const passwordStrength = zxcvbn(password);
    if (password.length < 6) {
        res.render('passport/signup', {
            errorMessage: 'Your password needs 6 or more characters'
        });
        return;
    }
    if (passwordStrength.score === 0) {
        res.render('passport/signup', {
            errorMessage: passwordStrength.feedback.warning
        });
        return;
    }

    User.findOne({ username })
        .then(user => {
            if (user) {
                res.render('passport/signup', {
                    errorMessage: 'There is already a registered user with this username'
                });
                return;
            }
            User.create({ username, password: hashPassword })
                .then(() => {
                    res.redirect('/');
                })
                .catch(err => {
                    console.error('Error while registering new user', err);
                    next();
                });
        })
        .catch(err => {
            console.error('Error while looking for user', err);
        });
});

const ensureLogin = require('connect-ensure-login');

passportRouter.get('/private-page', ensureLogin.ensureLoggedIn(), (req, res) => {
    res.render('passport/private', { user: req.user });
});

passportRouter.get('/login', (req, res) => {
    res.render('passport/login');
    errorMessage: req.flash('error');
});

passportRouter.post(
    '/login',
    passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/passport/login',
        failureFlash: true,
        passReqToCallback: true
    })
);

module.exports = passportRouter;
