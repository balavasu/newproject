// library to send email notifications
const nodemailer = require('nodemailer');

let sendEmail = (toEmail, ccEmail, emailTitle, emailMessage) => {
    return new Promise((resolve, reject) => {
        // define transporter
        var transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: '587',
            secureConnection: 'false',
            tls: {
                ciphers: 'SSLv3',
                rejectUnauthorized: false
            },
            auth: {
                user: '',
                pass: ''
            }
        });
        // define mail options
        const mailOptions = {
            from: '',
            to: toEmail,
            cc: ccEmail,
            subject: `Meeting planner notification: ${emailTitle}`,
            html: emailMessage
        };
        // send mail
        transporter.sendMail(mailOptions, function (err, info) {
            if (err) {
                logger.error('Sent Mail Failed!', 'emailLib.sendMail', 10);
                let response = response.generate(true, 'Server Error!Sent Mail Failed.', 500, null);
                reject(response);
            }
            else {
                logger.info('Mail Sent Successful!', 'emailLib.sendMail', 10);
                resolve(info);
            }
        });
    });
}

module.exports = {
    sendEmail: sendEmail
}
