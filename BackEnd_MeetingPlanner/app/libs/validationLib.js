/* email must match the valid email pattern */
let validateEmail = (email) => {
  let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/
  return email.match(emailRegex);
}

/* password length must be minimum 8 characters */
let validatePassword = (password) => {
 return (password && password.length >= 8);
}

module.exports = {
  validateEmail: validateEmail,
  validatePassword: validatePassword
}
