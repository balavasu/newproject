const express = require('express');
const meetingController = require("../controllers/meetingController");
const appConfig = require("./../../config/appConfig")
const auth = require('../middlewares/auth')

let setRouter = (app) => {
  let baseUrl = `${appConfig.apiVersion}/meeting`;

  app.post(`${baseUrl}/create`, auth.isAuthorized, meetingController.createMeeting);
  /**
   * @apiGroup Create
   * @apiVersion 1.0.0
   * @api {post} /api/v1/meeting/create Create Meeting
   * 
   * @apiParam {string} title Title of the meeting (body param) (required)
   * @apiParam {string} purpose Purpose of the meeting (body param) (required)
   * @apiParam {date} start Start date-time of meeting (body param) (required)
   * @apiParam {date} end End date-time of meeting (body param) (required)
   * @apiParam {string} location Location of the meeting (body param) (required)
   * @apiParam {string} inviter userId of the Admin who created meeting (body param) (required)
   * @apiParam {string} invitee userId of normal user for whom meeting created (body param) (required)
   * @apiParam {string} inviterEmail email address of the Admin who created meeting (body param) (required)
   * @apiParam {string} inviteeEmail email address of normal user for whom meeting created (body param) (required)
   * @apiParam {string} authToken Authorization Token(body param/header/query param) of the admin who created meeting (body param) (required)
   * 
   * 
   * 
   * @apiSuccessExample {object} Success-Response:
   * {
     "error":false,
     "message":"Meeting created",
     "status":200,
     "data":{
              "meetingId":"9CjoVE17X",
              "title":"Project review",
              "inviter":"n-jehKP5r",
              "invitee":"7WMr_3O_D",
              "purpose":"Report the current status of the project",
              "start":"2019-06-24T16:00:30.000Z",
              "end":"2019-06-24T17:00:30.000Z",
              "location":"Cabin#2514, Tower 2, 5th floor",
              "inviterEmail":"rinkesh2233@gmail.com",
              "inviteeEmail":"rshah@gmail.com",
              "timestamp":"2019-06-24T06:15:38.000Z",
              "_id":"5d106a8a9b8b2e3528a6330d",
              "__v":0
            }
      }
   */

  app.get(`${baseUrl}/getByInviterAndInvitee`, auth.isAuthorized, meetingController.getMeetingsByInviterAndInvitee);
   /**
   * @apiGroup Read
   * @apiVersion 1.0.0
   * @api {get} /api/v1/meeting/getByInviterAndInvitee  Get Meetings by combination of inviter and invitee
   * 
   * @apiParam {string} authToken Authorization(body param/header/query param) Token of the admin (body param) (required)
   * @apiParam {string} inviter userId of admin who created meeting (body param) (required)
   * @apiParam {string} invitee userId of normal user for whom meeting created (body param) (required)
   * @apiSuccess {object} myResponse shows error status, message, http stataus code, result
   * 
   * @apiSuccessExample {object} Success-Response:
   * {
      "error":false,
      "message":"Meeting found",
      "status":200,
      "data":[
              {
                "meetingId":"hmO4fh-WT",
                "title":"Project review",
                "inviter":"n-jehKP5r",
                "invitee":"7WMr_3O_D",
                "purpose":"Report the status of the project",
                "start":"2019-06-24T15:00:05.000Z",
                "end":"2019-06-24T16:00:05.000Z",
                "location":"Cabin#2514, Tower 2, 5th floor",
                "inviterEmail":"rinkesh2233@gmail.com",
                "inviteeEmail":"eshah@gmail.com",
                "timestamp":"2019-06-24T06:05:35.000Z"
              },
              {
                "meetingId":"CSNuqYFDp",
                "title":"Project grooming",
                "inviter":"n-jehKP5r",
                "invitee":"7WMr_3O_D",
                "purpose":"Analysis of project requirements",
                "start":"2019-07-01T15:00:00.000Z",
                "end":"2019-07-01T16:00:00.000Z",
                "location":"Cabin#1408, Tower 1, 4th floor",
                "inviterEmail":"rinkesh2233@gmail.com",
                "inviteeEmail":"eshah@gmail.com",
                "timestamp":"2019-06-24T06:38:00.000Z"
              }
            ]
          }
   */

  app.put(`${baseUrl}/update/:meetingId`, auth.isAuthorized, meetingController.updateMeeting);
   /**
   * @apiGroup Update
   * @apiVersion 1.0.0
   * @api {put} /api/v1/meeting/update/:meetingId Update meeting
   * 
   * @apiParam {string} meetingId Meeting ID of the meeting
   * @apiParam {string} title Title of the meeting (body param) (required)
   * @apiParam {string} purpose Purpose of the meeting (body param) (required)
   * @apiParam {date} start Start date-time of meeting (body param) (required)
   * @apiParam {date} end End date-time of meeting (body param) (required)
   * @apiParam {string} location Location of the meeting (body param) (required)
   * @apiParam {string} inviter userId of the Admin who created meeting (body param) (required)
   * @apiParam {string} invitee userId of normal user for whom meeting created (body param) (required)
   * @apiParam {string} inviterEmail email address of the Admin who created meeting (body param) (required)
   * @apiParam {string} inviteeEmail email address of normal user for whom meeting created (body param) (required)
   * @apiParam {string} authToken Authorization Token(body param/header/query param) of the admin who created meeting (body param) (required)
   * 
   * 
   * @apiSuccess {object} myResponse shows error status, message, http status code, result
   * 
   * @apiSuccessExample {object} Success-Response:
   * {
      "error":false,
      "message":"Meeting updated",
      "status":200,
      "data":{"n":1,"nModified":1,"ok":1}
    }
   */

  app.post(`${baseUrl}/delete/:meetingId`, auth.isAuthorized, meetingController.deleteMeeting);
   /**
   * @apiGroup Delete
   * @apiVersion 1.0.0
   * @api {post} /api/v1/meeting/delete/:meetingId Delete Meeting
   * 
   * @apiParam {string} meetingId Meeting Id of the meeting which is to be deleted
   * @apiParam {string} authToken Authorization Token of the admin who delete the meeting
   * 
   * 
   * 
   * @apiSuccessExample {object} Success-Response:
   * {
      "error":false,
      "message":"Meeting deleted",
      "status":200,
      "data":{
              "meetingId":"xnRqTIECP",
              "title":"Project demo",
              "inviter":"n-jehKP5r",
              "invitee":"7WMr_3O_D",
              "purpose":"Demo the project",
              "start":"2019-06-28T11:00:12.000Z",
              "end":"2019-06-28T12:00:12.000Z",
              "location":"Cabin#2416, Tower 2, 4th floor",
              "inviterEmail":"rinkesh2233@gmail.com",
              "inviteeEmail":"rinkeshpatel22@gmail.com",
              "timestamp":"2019-06-24T06:41:27.000Z",
              "_id":"5d10709769fe1f3c58b5db90",
              "__v":0
            }
      }
   */



  app.get(`${baseUrl}/getByInvitee/:inviteeId`, auth.isAuthorized, meetingController.getMeetingsByInvitee);
   /**
   * @apiGroup Read
   * @apiVersion 1.0.0
   * @api {get} /api/v1/meeting/getByInvitee/:inviteeId Get Meetings by invitee
   * 
   * @apiParam {string} authToken Authorization(body param/header/query param) Token of the admin (body param) (required)
   * @apiParam {string} inviteeId User ID of normal user for whom meetings created (body param) (required)
   * 
   * @apiSuccess {object} myResponse shows error status, message, http stataus code, result
   * 
   * @apiSuccessExample {object} Success-Response:
   * {
      "error":false,
      "message":"Meeting found",
      "status":200,
      "data":[
              {
                "meetingId":"hmO4fh-WT",
                "title":"Project review",
                "inviter":"n-jehKP5r",
                "invitee":"7WMr_3O_D",
                "purpose":"Report the status of the project",
                "start":"2019-06-24T15:00:00.000Z",
                "end":"2019-06-24T16:00:00.000Z",
                "location":"Cabin#2516, Tower 2, 5th floor",
                "inviterEmail":"rinkesh2233@gmail.com",
                "inviteeEmail":"eshah@gmail.com",
                "timestamp":"2019-06-24T06:05:35.000Z"
              },
              {
                "meetingId":"CSNuqYFDp",
                "title":"Project grooming",
                "inviter":"n-jehKP5r",
                "invitee":"7WMr_3O_D",
                "purpose":"Analysis of project requirements",
                "start":"2019-07-01T15:00:00.000Z",
                "end":"2019-07-01T16:00:00.000Z",
                "location":"Cabin#1408, Tower 1, 4th floor",
                "inviterEmail":"rinkesh2233@gmail.com",
                "inviteeEmail":"eshah@gmail.com",
                "timestamp":"2019-06-24T06:38:00.000Z"
              }
            ]
          }
   */

  app.get(`${baseUrl}/getByInviter/:inviterId`, auth.isAuthorized, meetingController.getMeetingsByInviter);
    /**
   * @apiGroup Read
   * @apiVersion 1.0.0
   * @api {get} /api/v1/meeting/getByInviter/:inviterId Get Meetings by inviter
   * 
   * @apiParam {string} authToken Authorization(body param/header/query param) Token of the admin (body param) (required)
   * @apiParam {string} inviterId User ID of admin who created meeting (body param) (required)
   * 
   * @apiSuccess {object} myResponse shows error status, message, http stataus code, result
   * 
   * @apiSuccessExample {object} Success-Response:
   * {
      "error":false,
      "message":"Meeting found",
      "status":200,
      "data":[
              {
                "meetingId":"hmO4fh-WT",
              "title":"Project review",
              "inviter":"n-jehKP5r",
              "invitee":"7WMr_3O_D",
              "purpose":"Report the status of the project",
              "start":"2019-06-24T15:00:05.000Z",
              "end":"2019-06-24T16:00:05.000Z",
              "location":"Cabin#2514, Tower 2, 5th floor",
              "inviterEmail":"rinkesh2233@gmail.com",
              "inviteeEmail":"eshah@gmail.com",
              "timestamp":"2019-06-24T06:05:35.000Z"
            },
            {
              "meetingId":"CSNuqYFDp",
              "title":"Project grooming",
              "inviter":"n-jehKP5r",
              "invitee":"7WMr_3O_D",
              "purpose":"Analysis of project requirements",
              "start":"2019-07-01T15:00:00.000Z",
              "end":"2019-07-01T16:00:00.000Z",
              "location":"Cabin#1408, Tower 1, 4th floor",
              "inviterEmail":"rinkesh2233@gmail.com",
              "inviteeEmail":"eshah@gmail.com",
              "timestamp":"2019-06-24T06:38:00.000Z"
            },
            {
              "meetingId":"xnRqTIECP",
              "title":"Project demo",
              "inviter":"n-jehKP5r",
              "invitee":"qG8N0b3yL",
              "purpose":"Demo the project",
              "start":"2019-06-28T11:00:12.000Z",
              "end":"2019-06-28T12:00:12.000Z",
              "location":"Cabin#2416, Tower 2, 4th floor",
              "inviterEmail":"rinkesh2233@gmail.com",
              "inviteeEmail":"rinkeshpatel22@gmail.com",
              "timestamp":"2019-06-24T06:41:27.000Z"
            }
          ]
        }
   */
}

module.exports = {
  setRouter: setRouter
}