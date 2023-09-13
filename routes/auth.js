const express = require('express');
const { check, body } = require('express-validator') //quando importar um pacote, exporta-se funções específicas assim, onde o '/check' indica a função

const authController = require('../controllers/auth');
const User = require('../models/user');

const router = express.Router();

router.get('/login', authController.getLogin);

router.get('/signup', authController.getSignup);

router.post('/login',
    [
        body('email')
            .isEmail()
            .withMessage('Please insert an valid e-mail')
            .normalizeEmail(),
        body('password')
        .isLength({min: 5})
        .trim()
        .isAlphanumeric()
    ], authController.postLogin);

router.post('/signup',
    [
        check('email')
            .isEmail()
            .withMessage('Please enter a valid email')
            .custom((value, { req }) => {
                // if (value === 'test@test.com') {
                //     throw new Error('This email address is forbidden')
                // }
                // return true
                return User.findOne({ email: value })
                    .then(userDoc => {
                        if (userDoc) {
                            return Promise.reject('error. This e-mail is already been used')
                        }
                    })
            })
            .normalizeEmail(),
        body('password',
            'Please enter a password with only numbers and text and with at least 5 characters.')
            .isLength({ min: 5 })
            .trim()
            .isAlphanumeric(),
        body('confirmPassword')
            .trim().custom((value, { req }) => {
                if (value !== req.body.password) {
                    throw new Error('Password have to match!');
                }
                return true
            })
    ],
    authController.postSignup);

router.post('/logout', authController.postLogout);

router.get('/reset', authController.getReset);

router.post('/reset', authController.postReset);

router.get('/reset/:token', authController.getNewPassword)

router.post('/new-password', authController.postNewPassword)

module.exports = router;