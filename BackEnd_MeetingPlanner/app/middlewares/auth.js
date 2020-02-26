const mongoose = require('mongoose');
const Auth = mongoose.model('Auth');
const logger = require('./../libs/loggerLib');
const responseLib = require('./../libs/responseLib');
const token = require('./../libs/tokenLib');
const check = require('./../libs/checkLib');

let isAuthorized = (req, res, next) => {
  if (req.params.authToken || req.query.authToken || req.body.authToken || req.header('authToken')) {
    Auth.findOne({authToken: req.header('authToken') || req.params.authToken || req.body.authToken || req.query.authToken}, (err, authDetails) => {
      if (err) {
        logger.error(err.message, 'auth middleware: isAuthorized()', 10);
        let response = responseLib.generate(true, 'Internal server error, failed to find authtoken', 500, null);
        res.status(500).send(response);
      } else if (check.isEmpty(authDetails)) {
        logger.error('Authtoken expired or not found', 'auth middleware: isAuthorized()', 10);
        let response = responseLib.generate(true, 'Authorization key expired or invalid', 404, null);
        res.status(404).send(response);
      } else {
        token.verifyToken(authDetails.authToken,authDetails.tokenSecret,(err,decoded)=>{
            if(err){
                logger.error('Failed to verify token', 'auth middleware: isAuthorized()', 10);
                let response = responseLib.generate(true, 'Internal server error, failed to verify token', 500, null);
                res.status(500).send(response);
            }
            else{
                req.user = {userId: decoded.data.userId};
                next();
            }
        });
      }
    })
  } else {
    logger.error('AuthorizationToken missing', 'auth middleware: isAuthorized()', 5);
    let response = responseLib.generate(true, 'AuthorizationToken missing', 400, null);
    res.send(response);
  }
}

module.exports = { isAuthorized: isAuthorized };
