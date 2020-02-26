// library to compare password
const bcrypt = require('bcryptjs');
const loggerLib = require('../libs/loggerLib');
const saltRounds = 10;

let hashpassword = (myPlaintextPassword) => {
  let salt = bcrypt.genSaltSync(saltRounds);
  let hash = bcrypt.hashSync(myPlaintextPassword, salt);
  return hash;
}

let comparePassword = (oldPassword, hashpassword, cb) => {
  // function to compare password
  bcrypt.compare(oldPassword, hashpassword, (err, res) => {
    if (err) {
      loggerLib.error(err.message, 'Comparison Error', 5);
      cb(err, null);
    } else {
      cb(null, res);
    }
  })
}

let comparePasswordSync = (myPlaintextPassword, hash) => {
  return bcrypt.compareSync(myPlaintextPassword, hash);
}

module.exports = {
  hashpassword: hashpassword,
  comparePassword: comparePassword,
  comparePasswordSync: comparePasswordSync
}
