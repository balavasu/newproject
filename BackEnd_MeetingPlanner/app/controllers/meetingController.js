const mongoose = require('mongoose');
const shortid = require('shortid');
const moment = require('moment');
const responseLib = require('./../libs/responseLib');
const emailLib = require('../libs/emailLib');
const checkLib = require('../libs/checkLib');
const MeetingModel = mongoose.model('Meeting');

/*---------CREATE MEETING START----------------*/
let createMeeting = (req, res) => {
    let validateRequest = () => {
        return new Promise((resolve, reject) => {
            if (req.body.title && req.body.start && req.body.end && req.body.inviter &&
                req.body.invitee && req.body.location && req.body.purpose) {
                resolve(req);
            } else {
                let response = responseLib.generate(true, 'Some required fields of meeting are missing.', 400, null);
                reject(response);
            }
        })
    };
    let saveMeeting = () => {
        return new Promise((resolve, reject) => {
            let newMeeting = new MeetingModel({
                meetingId: shortid.generate(),
                title: req.body.title,
                inviter: req.body.inviter,
                invitee: req.body.invitee,
                purpose: req.body.purpose,
                start: req.body.start,
                end: req.body.end,
                location: req.body.location,
                inviterEmail: req.body.inviterEmail,
                inviteeEmail: req.body.inviteeEmail,
                timestamp: moment.utc().format(),
            });
            newMeeting.save((err, result) => {
                if (err) {
                    let response = responseLib.generate(true, 'Internal server error, falied to save the meeting.', 500, null);
                    reject(response);
                } else {
                    let createdMeeting = result.toObject();
                    emailLib.sendEmail(createdMeeting.inviteeEmail, createdMeeting.inviterEmail, createdMeeting.title,
                        `Dear user, <br/><br/> A new meeting has been scheduled for you:<br/> 
                        ${prepareEmailMessage(createdMeeting)}`);
                    resolve(createdMeeting);
                }
            })
        })
    };
    validateRequest(req, res)
        .then(saveMeeting)
        .then((resolve) => {
            let response = responseLib.generate(false, 'Meeting created', 200, resolve);
            res.send(response)
        }).catch(err => res.send(err));
};
/*---------CREATE MEETING END----------------*/

/*---------UPDATE MEETING START----------------*/
let updateMeeting = (req, res) => {
    let findMeetings = () => {
        return new Promise((resolve, reject) => {
            MeetingModel.findOne({
                meetingId: req.params.meetingId
            }, (err, result) => {
                if (err) {
                    let response = responseLib.generate(true, 'error finding meeting', 500, null);
                    reject(response)
                } else if (checkLib.isEmpty(result)) {
                    let response = responseLib.generate(true, 'failed to find meeting', 404, null);
                    reject(response);
                } else {
                    resolve(result);
                }
            })
        })
    }
    let update = (result) => {
        return new Promise((resolve, reject) => {
            let options = req.body
            MeetingModel.update({
                meetingId: req.params.meetingId
            }, options, (err, updateResult) => {
                if (err) {
                    let response = responseLib.generate(true, 'failed to update meeting', 500, null);
                    reject(response);
                } else if (checkLib.isEmpty(updateResult)) {
                    let response = responseLib.generate(true, 'error finding meeting', 404, null);
                    reject(response);
                } else {
                    let updatedMeeting = req.body;
                    emailLib.sendEmail(updatedMeeting.inviteeEmail, updatedMeeting.inviterEmail, updatedMeeting.title,
                        `Dear user, <br/><br/> Your meeting with title: (${updatedMeeting.title}) has been updated as below: <br/> 
                        ${prepareEmailMessage(updatedMeeting)}`);
                    resolve(updateResult);
                }
            })
        })
    }
    findMeetings()
        .then(update)
        .then((resolve) => {
            let response = responseLib.generate(false, 'Meeting updated', 200, resolve);
            res.send(response)
        }).catch((err) => res.send(err));
}
/*---------UPDATE MEETING END----------------*/

/*---------DELETE MEETING START----------------*/
let deleteMeeting = (req, res) => {
    let findMeeting = () => {
        return new Promise((resolve, reject) => {
            MeetingModel.findOne({
                meetingId: req.params.meetingId
            }, (err, result) => {
                if (err) {
                    let response = responseLib.generate(true, 'Internal server error, falied to find meeting', 500, null);
                    reject(response);
                } else if (checkLib.isEmpty(result)) {
                    let response = responseLib.generate(true, 'Meeting not found', 404, null);
                    reject(response);
                } else {
                    resolve(result);
                }
            })
        })
    }
    let deleteThisMeeting = (result) => {
        return new Promise((resolve, reject) => {
            MeetingModel.findOneAndRemove({
                meetingId: req.params.meetingId
            }, (err, deleteResult) => {
                if (err) {
                    let response = responseLib.generate(true, 'Internal server error, failed to delete meeting', 500, null);
                    reject(response);
                } else if (checkLib.isEmpty(deleteResult)) {
                    let response = responseLib.generate(true, 'Meeting not found', 404, null);
                    reject(response);
                } else {
                    emailLib.sendEmail(result.inviteeEmail, result.inviterEmail, result.title,
                        `Dear user, <br/><br/> Your below meeting has been cancled: <br/> 
                        ${prepareEmailMessage(result)}`);
                    resolve(deleteResult);
                }
            })
        })
    }
    findMeeting()
        .then(deleteThisMeeting)
        .then((resolve) => {
            let response = responseLib.generate(false, 'Meeting deleted', 200, resolve);
            res.send(response)
        }).catch((err) => res.send(err));
}
/*---------DELETE MEETING END----------------*/

/*---------GET MEETING BY INVITER AND INVITEE START----------------*/
let getMeetingsByInviterAndInvitee = (req, res) => {
    let validateRequest = () => {
        return new Promise((resolve, reject) => {
            if (checkLib.isEmpty(req.query.inviter) || checkLib.isEmpty(req.query.invitee)) {
                let response = responseLib.generate(true, 'Some parameters missing', 400, null);
                reject(response);
            } else {
                resolve();
            }
        })
    }
    let findMeetings = () => {
        return new Promise((resolve, reject) => {
            let findQuery = { $and: [{ inviter: req.query.inviter }, { invitee: req.query.invitee }] };
            MeetingModel.find(findQuery)
                .select('-_id -__v')
                .lean()
                .exec((err, result) => {
                    if (err) {
                        let response = responseLib.generate(true, 'Internal server error while finding meeting for selected user', 500, null);
                        reject(response);
                    } else if (checkLib.isEmpty(result)) {
                        let response = responseLib.generate(true, 'No meetings found for selected user', 404, null);
                        reject(response);
                    } else {
                        resolve(result);
                    }
                })
        });
    }
    validateRequest()
        .then(findMeetings)
        .then((resolve) => {
            let response = responseLib.generate(false, 'Meeting found', 200, resolve);
            res.send(response);
        }).catch((err) => res.send(err));
}
/*---------GET MEETING BY INVITER AND INVITEE END----------------*/

/*---------GET MEETING BY INVITER START----------------*/
let getMeetingsByInviter = (req, res) => {
    let validateRequest = () => {
        return new Promise((resolve, reject) => {
            if (checkLib.isEmpty(req.params.inviterId)) {
                let response = responseLib.generate(true, 'parameters missing', 403, null);
                reject(response);
            } else {
                resolve();
            }
        })
    }
    let findMeetings = () => {
        return new Promise((resolve, reject) => {
            MeetingModel.find({ inviter: req.params.inviterId })
                .select('-_id -__v')
                .lean()
                .exec((err, result) => {
                    if (err) {
                        let response = responseLib.generate(true, 'Internal server error while finding meeting for selected user', 500, null);
                        reject(response);
                    } else if (checkLib.isEmpty(result)) {
                        let response = responseLib.generate(true, 'No meetings found for selected user', 404, null);
                        reject(response);
                    } else {
                        resolve(result);
                    }
                })
        })
    }
    validateRequest()
        .then(findMeetings)
        .then((resolve) => {
            let response = responseLib.generate(false, 'Meeting found', 200, resolve);
            res.send(response);
        }).catch((err) => res.send(err));
}
/*---------GET MEETING BY INVITER END----------------*/

/*---------GET MEETING BY INVITEE START----------------*/
let getMeetingsByInvitee = (req, res) => {
    let validateRequest = () => {
        return new Promise((resolve, reject) => {
            if (checkLib.isEmpty(req.params.inviteeId)) {
                let response = responseLib.generate(true, 'parameters missing', 403, null);
                reject(response);
            } else {
                resolve();
            }
        })
    }
    let findMeetings = () => {
        return new Promise((resolve, reject) => {
            MeetingModel.find({ invitee: req.params.inviteeId })
                .select('-_id -__v')
                .lean()
                .exec((err, result) => {
                    if (err) {
                        let response = responseLib.generate(true, 'Internal server error while finding meeting for selected user', 500, null);
                        reject(response);
                    } else if (checkLib.isEmpty(result)) {
                        let response = responseLib.generate(true, 'No meetings found for selected user', 404, null);
                        reject(response);
                    } else {
                        resolve(result);
                    }
                })
        })
    }
    validateRequest()
        .then(findMeetings)
        .then((resolve) => {
            let response = responseLib.generate(false, 'Meeting found', 200, resolve);
            res.send(response);
        }).catch((err) => res.send(err));
}
/*---------GET MEETING BY INVITEE END----------------*/

/*---------PRIVATE METHODS START----------------*/
let prepareEmailMessage = (meeting) => {
    return `<b>Title: </b>${meeting.title}<br/>
            <b>Purpose: </b>${meeting.purpose}<br/>
            <b>Start: </b>${getDateObject(meeting.start)}<br/> 
            <b>End: </b>${getDateObject(meeting.end)}<br/> 
            <b>Location: </b>${meeting.location}<br/>
            <b>Inviter: </b>${meeting.inviterEmail}<br/><br/><br/>
            Cheers, <br/>
            Meeting Planner.`;
}

let getDateObject = (date) =>{
    return new Date(
        new Date(date).getUTCFullYear(),
        new Date(date).getUTCMonth(),
        new Date(date).getUTCDate(),
        new Date(date).getUTCHours(),
        new Date(date).getUTCMinutes());
}
/*---------PRIVATE METHODS END----------------*/

module.exports = {
    createMeeting: createMeeting,
    updateMeeting: updateMeeting,
    deleteMeeting: deleteMeeting,
    getMeetingsByInviterAndInvitee: getMeetingsByInviterAndInvitee,
    getMeetingsByInviter: getMeetingsByInviter,
    getMeetingsByInvitee: getMeetingsByInvitee
}