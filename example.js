const express = require('express');
const router = express.Router();
const crypto = require('crypto');

//generates a salt

const generateSalt = function (length) {
    return crypto.randomBytes(length)
        .toString('hex')
        .slice(0, length);
}

//hashPassword

const hashPassword = function (password, salt) {
    const hash = crypto.createHmac('sha512', salt);
    hash.update(password);
    const value = hash.digest('hex');
    return {
        salt: salt,
        hashedPassword: value
    };
};

//combine the hash and salt (synchronously)

function saltAndHash(userpassword) {
    const salt = generateSalt(256);
    const passwordData = hashPassword(userpassword, salt);
    console.log('User Password = ' + userpassword);
    console.log('salt = ' + salt);
    console.log('salted and hashed = ' + passwordData.hashedPassword);
    return passwordData;
}

saltAndHash('test');
saltAndHash('test');

module.exports = router;    