const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const app = express();
const mongoose = require('mongoose');
const appConfig = require('./config/appConfig');
const socketLib = require('./app/libs/socketLib');
mongoose.set('useCreateIndex', true);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.all('*', (req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    next();
});

// require models
const modelsPath = './app/models';
fs.readdirSync(modelsPath).forEach(file => {
    if (~file.indexOf('.js')) {
        require(modelsPath + '/' + file)
    }
});
// require routes
const routesPath = './app/routes'
fs.readdirSync(routesPath).forEach(file => {
    if (~file.indexOf('.js')) {
        let route = require(routesPath + '/' + file);
        route.setRouter(app);
    }
});

// Handlers
// handle specific listen errors with friendly messages
let serverErrorHandler = (error) => {
    if (error.syscall !== 'listen') {
        throw error;
    }
    switch (error.code) {
        case 'EACCES':
            process.exit(1);
            break;
        case 'EADDRINUSE':
            process.exit(1);
            break;
        default:
            throw error;
    }
};
let serverListeningHandler = () => {
    var addr = server.address();
    var bind = typeof addr === 'string' ?
        'pipe ' + addr :
        'port ' + addr.port;
    ('Listening on ' + bind);
    mongoose.connect(appConfig.db.uri, { useNewUrlParser: true });
    console.log('Port ' + appConfig.port + ' is ready...!')
};
let mongooseErrorHandler = (err) => {
    console.log('Database connection error: ' + err);
};
let mongooseConnectionHandler = (err) => {
    if (err) {
        console.log("Database error: " + err);
    } else {
        console.log("Database connected successfully..!");
    }
}
// application specific logging, throwing an error, or other logic here
let processRejectionHandler = (reason, p) => {
    console.log('Unhandled Rejection at: Promise', p, 'reason:', reason);
};

// start server, connect mongo db and handle events 
const server = app.listen(appConfig.port);
server.on('error', serverErrorHandler);
server.on('listening', serverListeningHandler);
mongoose.connection.on('error', mongooseErrorHandler);
mongoose.connection.on('open', mongooseConnectionHandler);
socketLib.setServer(server);
process.on('unhandledRejection', processRejectionHandler);

module.exports = app;