// Library to manage authorization token
const jwt = require('jsonwebtoken')
const shortid = require('shortid')
const secretKey = 'thisIsRandomSecretKey';
const loggerLib = require('../libs/loggerLib');

let generateToken = (data, cb) => {
  // funtion to generate token
  try {
    let claims = {
      jwtid: shortid.generate(),
      iat: Date.now(),
      exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24),
      sub: 'authToken',
      iss: 'meetingPlanner',
      data: data
    }
    let tokenDetails = {
      token: jwt.sign(claims, secretKey),
      tokenSecret : secretKey
    }
    cb(null, tokenDetails);
  } catch (err) {
    loggerLib.error('Failed to generatet token', 'tokenLib generateToken()');
    cb(err, null);
  }
}

let verifyClaim = (token,secretKey,cb) => {
  // function to verify the token
  jwt.verify(token, secretKey, function (err, decoded) {
    if(err){
      loggerLib.error("Failed to verify token", "tokenLib verifyClaim()");
      cb(err,null);
    }
    else{
      cb(null,decoded);
    }  
  });
}

module.exports = {
  generateToken: generateToken,
  verifyToken :verifyClaim
}
