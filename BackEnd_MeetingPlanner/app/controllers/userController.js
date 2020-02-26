const mongoose = require('mongoose');
const shortid = require('shortid');
const moment = require('moment');
const passwordLib = require('./../libs/passwordLib');
const responseLib = require('./../libs/responseLib');
const loggerLib = require('../libs/loggerLib');
const validationLib = require('../libs/validationLib');
const checkLib = require('../libs/checkLib');
const tokenLib = require('../libs/tokenLib');
const AuthModel = mongoose.model('Auth');
const UserModel = mongoose.model('User');
const emailLib = require('../libs/emailLib');

/*----------SIGNUP START ---------*/
let signUp = (req, res) => {
    let validateUserInput = () => {
        return new Promise((resolve, reject) => {
            if (req.body.email) {
                if (!validationLib.validateEmail(req.body.email)) {
                    let response = responseLib.generate(true, 'Invalid email id', 400, null);
                    reject(response);
                } else if (!validationLib.validatePassword(req.body.password)) {
                    let response = responseLib.generate(true, 'Password length must be minimum 8 characters', 400, null);
                    reject(response);
                } else {
                    resolve(req);
                }
            } else {
                let response = responseLib.generate(true, 'Bad request, some parameter is missing', 400, null);
                reject(response);
            }
        });
    }

    let createUser = () => {
        return new Promise((resolve, reject) => {
            UserModel.findOne({
                email: req.body.email
            })
                .exec((err, retrievedUserDetails) => {
                    if (err) {
                        let response = responseLib.generate(true, 'Failed To Create User', 500, null)
                        reject(response)
                    } else if (checkLib.isEmpty(retrievedUserDetails)) {
                        let newUser = new UserModel({
                            userId: shortid.generate(),
                            userName: req.body.userName,
                            firstName: req.body.firstName,
                            lastName: req.body.lastName || '',
                            email: req.body.email.toLowerCase(),
                            isAdmin: req.body.isAdmin,
                            mobileNumber: req.body.mobileNumber,
                            password: passwordLib.hashpassword(req.body.password),
                            countryName: req.body.countryName,
                            countryCode: req.body.countryCode,
                            createdOn: moment.utc().format()
                        })
                        newUser.save((err, newUser) => {
                            if (err) {
                                loggerLib.error(err.message, 'userController: createUser', 10)
                                let response = responseLib.generate(true, 'Failed to create new User as some details are inappropriate', 500, null)
                                reject(response)
                            } else {
                                let newUserObj = newUser.toObject();
                                resolve(newUserObj)
                                emailLib.sendEmail(newUser.email, 'Welcome To the Meeting application')
                            }
                        })
                    } else {
                        loggerLib.error('User Cannot Be Created.User Already Present', 'userController: createUser', 4)
                        let response = responseLib.generate(true, 'User Already Present With this Email', 403, null)
                        reject(response)
                    }
                })
        });
    } 


    validateUserInput(req, res)
        .then(createUser)
        .then((resolve) => {
            delete resolve.password
            let response = responseLib.generate(false, 'User created', 200, resolve)
            res.send(response)
        })
        .catch((err) => {
            res.send(err);
        })

}
/*----------SIGNUP END ---------*/

/*----------LOGIN START ---------*/
let login = (req, res) => {
    let findUser = () => {
        return new Promise((resolve, reject) => {
            if (req.body.email) {
                UserModel.findOne({ email: req.body.email },
                    (err, userDetails) => {
                        if (err) {
                            loggerLib.error('Failed to find user', 'userController: findUser()');
                            let response = responseLib.generate(true, 'Internal server error, failed to find user', 500, null);
                            reject(response);
                        } else if (checkLib.isEmpty(userDetails)) {
                            let response = responseLib.generate(true, 'User not found with this email id', 404, null)
                            reject(response);
                        } else {
                            resolve(userDetails);
                        }
                    });

            } else {
                let response = responseLib.generate(true, 'Bad request, email missing', 400, null);
                reject(response);
            }
        })
    }
    let validatePassword = (retrievedUserDetails) => {
        return new Promise((resolve, reject) => {
            passwordLib.comparePassword(req.body.password, retrievedUserDetails.password, (err, isMatch) => {
                if (err) {
                    loggerLib.error(err.message, 'userController: validatePassword()', 10)
                    let response = responseLib.generate(true, 'Login Failed', 500, null)
                    reject(response)
                } else if (isMatch) {
                    let retrievedUserDetailsObj = retrievedUserDetails.toObject()
                    delete retrievedUserDetailsObj.password
                    delete retrievedUserDetailsObj._id
                    delete retrievedUserDetailsObj.__v
                    delete retrievedUserDetailsObj.createdOn
                    delete retrievedUserDetailsObj.modifiedOn
                    resolve(retrievedUserDetailsObj)
                } else {
                    loggerLib.info('Login Failed Due To Invalid Password', 'userController: validatePassword()', 10)
                    let response = responseLib.generate(true, 'Invalid Password', 400, null)
                    reject(response)
                }
            })
        })
    }

    let generateToken = (userDetails) => {
        return new Promise((resolve, reject) => {
            tokenLib.generateToken(userDetails, (err, tokenDetails) => {
                if (err) {
                    let response = responseLib.generate(true, 'Failed To Generate Token', 500, null)
                    reject(response)
                } else {
                    tokenDetails.userId = userDetails.userId
                    tokenDetails.userDetails = userDetails
                    resolve(tokenDetails)
                }
            })
        })
    }
    let saveToken = (tokenDetails) => {
        return new Promise((resolve, reject) => {
            AuthModel.findOne({
                userId: tokenDetails.userId
            }, (err, retrievedTokenDetails) => {
                if (err) {
                    let response = responseLib.generate(true, 'Failed To Generate Token', 500, null)
                    reject(response)
                } else if (checkLib.isEmpty(retrievedTokenDetails)) {
                    let newAuthToken = new AuthModel({
                        userId: tokenDetails.userId,
                        authToken: tokenDetails.token,
                        tokenSecret: tokenDetails.tokenSecret,
                        tokenGenerationTime: moment.utc().format()
                    })
                    newAuthToken.save((err, newTokenDetails) => {
                        if (err) {
                            let response = responseLib.generate(true, 'Failed To Generate Token', 500, null)
                            reject(response)
                        } else {
                            let responseBody = {
                                authToken: newTokenDetails.authToken,
                                userDetails: tokenDetails.userDetails
                            }
                            resolve(responseBody)
                        }
                    })
                } else {
                    retrievedTokenDetails.authToken = tokenDetails.token
                    retrievedTokenDetails.tokenSecret = tokenDetails.tokenSecret
                    retrievedTokenDetails.tokenGenerationTime = moment.utc().format()
                    retrievedTokenDetails.save((err, newTokenDetails) => {
                        if (err) {
                            let response = responseLib.generate(true, 'Failed To Generate Token', 500, null)
                            reject(response)
                        } else {
                            let responseBody = {
                                authToken: newTokenDetails.authToken,
                                userDetails: tokenDetails.userDetails
                            }
                            resolve(responseBody)
                        }
                    })
                }
            })
        })
    }

    findUser(req, res)
        .then(validatePassword)
        .then(generateToken)
        .then(saveToken)
        .then((resolve) => {
            let response = responseLib.generate(false, 'Login Successful', 200, resolve)
            res.status(200)
            res.send(response)
        })
        .catch((err) => {
            res.status(err.status)
            res.send(err)
        })
}
/*----------LOGIN END ---------*/

/*----------LOGOUT START ---------*/
let logout = (req, res) => {
    AuthModel.findOneAndRemove({ userId: req.params.userId },
        (err, result) => {
            if (err) {
                let response = responseLib.generate(true, 'Internal server error, failed to logout', 500, null);
                res.send(response);
            } else if (checkLib.isEmpty(result)) {
                let response = responseLib.generate(true, 'User not found', 404, null);
                res.send(response);
            } else {
                let response = responseLib.generate(false, 'Logged out', 200, null);
                res.send(response);
            }
        });
}
/*----------LOGOUT END ---------*/

/*----------FORGOT PASSWORD START ---------*/
let forgotPassword = (req, res) => {
    let validateUserInput = () => {
        return new Promise((resolve, reject) => {
            if (checkLib.isEmpty(req.body.email)) {
                let response = responseLib.generate(true, 'Bad request, email is missing', 400, null);
                reject(response);
            } else {
                resolve(req);
            }
        })
    }
    let sendResetPasswordLink = () => {
        return new Promise((resolve, reject) => {
            UserModel.findOne({ email: req.body.email },
                (err, result) => {
                    if (err) {
                        let response = responseLib.generate(true, 'Internal server error, failed to find user', 500, null);
                        reject(response);
                    } else if (checkLib.isEmpty(result)) {
                        let response = responseLib.generate(true, 'User not found with this email', 404, null);
                        reject(response);
                    } else {
                        emailLib.sendEmail(result.email, null, "Plannin Meeting password reset",
                            `Dear user,<br/><br/> 
                        <a href='http://localhost:4200/resetPassword/${result.userId}'>
                        Click here to reset password</a><br/><br/><br>
                        Cheers,<br/>Planning Meeting.`);
                        let response = responseLib.generate(false, 'Email sent successfully to reset the password', 200, 'email sent');
                        resolve(response);
                    }
                })
        })
    }
    validateUserInput(req, res)
        .then(sendResetPasswordLink)
        .then((resolve) => {
            let response = responseLib.generate(false, 'email send successfully for password reset', 200, resolve)
            res.send(response);
        }).catch((err) => {
            let response = responseLib.generate(err.error, err.message, err.status, err.data);
            res.send(response);
        })
}
/*----------FORGOT PASSWORD END ---------*/

/*----------RESET PASSWORD START ---------*/
let resetPassword = (req, res) => {
    let findUser = () => {
        return new Promise((resolve, reject) => {
            if (req.body.userId) {
                UserModel.findOne({ userId: req.body.userId },
                    (err, userDetails) => {
                        if (err) {
                            let response = responseLib.generate(true, 'Internal server error, failed to find user', 500, null);
                            reject(response);
                        } else if (checkLib.isEmpty(userDetails)) {
                            let response = responseLib.generate(true, 'User not found', 404, null);
                            reject(response);
                        } else {
                            resolve(userDetails);
                        }
                    })
            } else {
                let response = responseLib.generate(true, 'Bad request, userId missing', 400, null);
                reject(response);
            }
        });
    }
    let updatePassword = (userDetails) => {
        return new Promise((resolve, reject) => {
            if (checkLib.isEmpty(req.body.password)) {
                let response = responseLib.generate(true, 'Bad request, password missing', 400, null);
                reject(response);
            } else {
                UserModel.update({ userId: req.body.userId },
                    { password: passwordLib.hashpassword(req.body.password) },
                    { multi: true },
                    (err, result) => {
                        if (err) {
                            let response = responseLib.generate(true, 'Internal server error, failed to change password', 500, null);
                            reject(response);
                        } else if (checkLib.isEmpty(result)) {
                            let response = responseLib.generate(true, 'User not found', 404, null);
                            reject(response);
                        } else {
                            emailLib.sendEmail(userDetails.email, null, "Plannin Meeting password reset",
                                `Dear user,<br/><br/> 
                                Your login password for Planning Meeting has been changed.<br/<br/>br/>
                                Cheers,<br/>Planning Meeting.`);
                            let response = responseLib.generate(false, 'Password changed', 200, null);
                            resolve(response);
                        }
                    });
            }
        });
    }
    findUser(req, res)
        .then(updatePassword)
        .then((resolve) => {
            res.status(200);
            let response = responseLib.generate(false, 'Pasword changed', 200, resolve);
            res.send(response);
        }).catch((err) => res.send(err));
}
/*----------RESET PASSWORD END ---------*/

/*----------GET USERS START ---------*/
let getUsers = (req, res) => {
    UserModel.find()
        .select(' -__v -_id')
        .lean()
        .exec((err, result) => {
            if (err) {
                loggerLib.error(err.message, 'User Controller: getAllUser()', 10);
                let response = responseLib.generate(true, 'Internal server error, failed to find users', 500, null);
                res.send(response);
            } else if (checkLib.isEmpty(result)) {
                let response = responseLib.generate(true, 'User not found', 404, null);
                res.send(response);
            } else {
                let response = responseLib.generate(false, 'User found', 200, result)
                res.send(response);
            }
        })
}
/*----------GET USERS END ---------*/

/*----------GET USER BY ID START ---------*/
let getUserById = (req, res) => {
    UserModel.findOne({ 'userId': req.params.userId })
        .select('-password -__v -_id')
        .lean()
        .exec((err, result) => {
            if (err) {
                loggerLib.error(err.message, 'userController: getUserById()')
                let response = responseLib.generate(true, 'Internal server error, failed to find user', 500, null)
                res.send(response);
            } else if (checkLib.isEmpty(result)) {
                let response = responseLib.generate(true, 'User not found', 404, null)
                res.send(response);
            } else {
                let response = responseLib.generate(false, 'User found', 200, result)
                res.send(response);
            }
        })
}
/*----------GET USER BY ID END ---------*/

/*----------DELETE USER START ---------*/
let deleteUser = (req, res) => {
    UserModel.findOneAndRemove({ 'userId': req.params.userId }).exec((err, result) => {
        if (err) {
            loggerLib.error(err.message, 'User Controller: deleteUser()');
            let response = responseLib.generate(true, 'Internal server error, failed to delete user', 500, null);
            res.send(response);
        } else if (checkLib.isEmpty(result)) {
            loggerLib.info('User not found', 'User Controller: deleteUser()');
            let response = responseLib.generate(true, 'User not found', 404, null);
            res.send(response);
        } else {
            let response = responseLib.generate(false, 'User deleted', 200, result);
            res.send(response);
        }
    });
}
/*----------DELETE USER END ---------*/

/*----------UPDATE USER START ---------*/
let updateUser = (req, res) => {
    let options = req.body;
    UserModel.update({ 'userId': req.params.userId }, options).exec((err, result) => {
        if (err) {
            loggerLib.error(err.message, 'User Controller:updateUser', 10);
            let response = responseLib.generate(true, 'Internal server error, failed to update user', 500, null);
            res.send(response);
        } else if (checkLib.isEmpty(result)) {
            let response = responseLib.generate(true, 'User not found', 404, null);
            res.send(response);
        } else {
            let response = responseLib.generate(false, 'User updated', 200, result);
            res.send(response);
        }
    });
}
/*----------UPDATE USER START ---------*/

module.exports = {
    signUp: signUp,
    login: login,
    logout: logout,
    forgotPassword: forgotPassword,
    resetPassword: resetPassword,
    getUsers: getUsers,
    getUserById: getUserById,
    deleteUser: deleteUser,
    updateUser: updateUser
}
