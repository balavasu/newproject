const mongoose = require('mongoose');
let Schema = mongoose.Schema;

let userSchema = new Schema({
  userId: {
    type: String,
    required: true,
    unique: true,
    index: true,
    default: ''
  },
  userName:{
    type: String,
    required: true,
    unique: true,
    default: ''
  },
  firstName: {
    type: String,
    default: '',
  },
  lastName: {
    type: String,
    default: '',
  },
  email: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true,
    default: 'password'
  },
  mobileNumber: {
    type: Number,
    default: '',
    minlength: 10,
    maxlength: 10,
    required: true
  },
  countryCode: {
    type: String,
    default: ''
  },
  isAdmin: {
    type: Boolean,
    default: 'false'
  }
});

mongoose.model('User', userSchema);