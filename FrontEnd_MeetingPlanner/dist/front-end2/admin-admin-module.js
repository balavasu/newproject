(window["webpackJsonp"] = window["webpackJsonp"] || []).push([["admin-admin-module"],{

/***/ "./src/app/admin/admin-dashboard.component.html":
/*!******************************************************!*\
  !*** ./src/app/admin/admin-dashboard.component.html ***!
  \******************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "<app-loader *ngIf=\"isLoading\"></app-loader>\n<!-- HEADER COMPONENT -->\n<app-header></app-header>\n<!-- ADMIN DASHBOARD -->\n<div class=\"container\">\n  <div class=\"row admin-dashboard\">\n    <!-- USER LIST START -->\n    <div class=\"col-12 user-list\" *ngIf=\"showUserList\">\n        <div *ngFor=\"let user of userSortedList\">\n          <div *ngIf=\"user.isAdmin==false\">\n            <div (click)=\"displaySelectedUserMeetings(user, true)\">\n              <div class=\"row at-user-box shadow-box-card\">\n                <div class=\"col-sm-1 user-icon\">\n                    <i class=\"fa fa-user\"></i>\n                </div>\n                <div class=\"col-sm-5 col-lg-2 at-ellipsis\">\n                    <span>{{user.userName}}</span>\n                </div>\n                <div class=\"col-sm-5 col-lg-2 at-ellipsis\">\n                  <span>{{user.fullName}}</span>\n                </div>\n                <div class=\"col-sm-5 col-lg-3 at-ellipsis at-email\">\n                    <i class=\"fa fa-envelope\"></i>\n                    <span>{{user.email}}</span>\n                </div>\n                <div class=\"col-sm-5 col-lg-3 at-ellipsis\">\n                    <i class=\"fa fa-phone-square\"></i>\n                    <span>{{user.mobile}}</span>\n                </div>\n                <div class=\"col-sm-2 col-lg-1 at-ellipsis\">\n                    <button class=\"btn btn-primary\" type=\"button\">select</button>\n                </div>\n              </div>\n            </div>\n          </div>\n        </div>\n    </div>\n    <!-- USER LIST END -->\n    <!-- CALENDAR VIEW START -->\n    <div class=\"col-12\" *ngIf=\"showCalender\">\n      <div class=\"row\">\n        <div class=\"col-12 at-nav-buttons\">\n          <div class=\"row\">\n           <div class=\"col-xs-12 col-sm-6 at-back-btn\">\n              <button class=\"btn btn-primary shadow-box-card\"\n              (click)=\"showCalender=false; showUserList=true; onClickBack()\">Back to user list</button>\n           </div>\n           <div class=\"col-xs-12 col-sm-6 at-create-btn\">\n              <button class=\"btn btn-primary shadow-box-card\" (click)=\"onCreateMeetingClicked()\">Create new Meeting</button>\n            </div>\n          </div>\n        </div>\n        <div class=\"col-12\">\n          <app-calendar [modalData]=\"modalData\" [meetings]=\"meetings\" (calendarEventEmitter)=\"onCalendarEvent($event)\">\n          </app-calendar>\n        </div>\n      </div>\n    </div>\n    <!-- CALENDAR VIEW END -->\n  </div>\n</div>\n\n<!-- MEETING FORM MODAL TEMPLATE -->\n<ng-template #meetingTemplate>\n  <div class=\"modal-header\">\n    <h4 class=\"modal-title pull-left\">\n      {{calendarAction == 'create'? 'Create a new meeting' : calendarAction == 'edit'? 'Update your meeting': ''}}</h4>\n    <button type=\"button\" class=\"close pull-right\" aria-label=\"Close\" (click)=\"meetingModalRef.hide()\">\n      <span aria-hidden=\"true\">&times;</span>\n    </button>\n  </div>\n  <div class=\"modal-body\">\n    <app-meeting [isEditMeeting]=\"isEditMeeting\" [selectedMeeting]=\"selectedMeeting\" [selectedDate]=\"selectedDate\"\n      (onFormClose)=\"closeMeetingModal()\">\n    </app-meeting>\n  </div>\n</ng-template>\n\n<!-- MEETING REMINDER MODAL TEMPLATE -->\n<ng-template #reminderTemplate let-close=\"close\">\n  <div class=\"modal-header\">\n    <h5 class=\"modal-title\">Meeting Reminder</h5>\n    <button type=\"button\" class=\"close\" (click)=\"snoozeRemiderModal()\">\n      <span aria-hidden=\"true\">&times;</span>\n    </button>\n  </div>\n  <div class=\"modal-body\">\n    <h6 class=\"card-title\">Your meeting <span><b>\"{{meetingEvent.title}}\"</b></span> will start soon.</h6>\n  </div>\n  <div class=\"modal-footer\">\n    <button type=\"button\" class=\"btn btn-outline-success\" (click)=\"snoozeRemiderModal()\">Snooze</button>\n    <button type=\"button\" class=\"btn btn-outline-secondary\" (click)=\"dismissRemiderModal()\">Dismiss</button>\n  </div>\n</ng-template>\n"

/***/ }),

/***/ "./src/app/admin/admin-dashboard.component.scss":
/*!******************************************************!*\
  !*** ./src/app/admin/admin-dashboard.component.scss ***!
  \******************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = ".at-nav-buttons {\n  padding: 20px 0;\n  text-align: center; }\n  .at-nav-buttons .at-back-btn button, .at-nav-buttons .at-create-btn button {\n    width: 170px; }\n  .at-nav-buttons .at-back-btn button:hover, .at-nav-buttons .at-create-btn button:hover {\n      box-shadow: 0px 0px 10px #777; }\n  @media only screen and (min-width: 576px) {\n    .at-nav-buttons .at-back-btn {\n      text-align: right; }\n    .at-nav-buttons .at-create-btn {\n      text-align: left; } }\n  .admin-dashboard .user-list {\n  margin-top: 40px; }\n  .at-user-box {\n  margin-bottom: 20px;\n  cursor: pointer; }\n  .at-user-box:hover {\n    box-shadow: 0px 0px 10px #777; }\n  .fa-user {\n  font-size: 40px;\n  position: absolute;\n  line-height: 40px; }\n  .at-ellipsis {\n  line-height: 40px; }\n  i {\n  color: #007bff; }\n  .fa-envelope, .fa-phone-square {\n  margin-right: 10px; }\n  @media only screen and (max-width: 1023px) {\n  .user-icon {\n    display: none; }\n  .at-email, .at-mobile {\n    line-height: 40px; } }\n  @media only screen and (max-width: 575px) {\n  .shadow-box-card {\n    width: 90%;\n    margin: 20px auto; } }\n\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9hcHAvYWRtaW4vQzpcXFVzZXJzXFxERUxMXFxuZXdcXE1lYW4tc3RhY2stYXBwMS1tZWV0aW5nLXBsYW5uZXItbWFzdGVyXFxGcm9udEVuZF9NZWV0aW5nUGxhbm5lci9zcmNcXGFwcFxcYWRtaW5cXGFkbWluLWRhc2hib2FyZC5jb21wb25lbnQuc2NzcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTtFQUNJLGVBQWU7RUFDZixrQkFBa0IsRUFBQTtFQUZ0QjtJQU1ZLFlBQVksRUFBQTtFQU54QjtNQVFnQiw2QkFBNkIsRUFBQTtFQUl6QztJQVpKO01BY1ksaUJBQWlCLEVBQUE7SUFkN0I7TUFpQlksZ0JBQWdCLEVBQUEsRUFDbkI7RUFHVDtFQUVRLGdCQUFnQixFQUFBO0VBR3hCO0VBQ0ksbUJBQW1CO0VBQ25CLGVBQWUsRUFBQTtFQUZuQjtJQUlRLDZCQUE2QixFQUFBO0VBR3JDO0VBQ0ksZUFBZTtFQUNmLGtCQUFrQjtFQUNsQixpQkFBaUIsRUFBQTtFQUVyQjtFQUNBLGlCQUFpQixFQUFBO0VBRWpCO0VBQ0ksY0FBYyxFQUFBO0VBRWxCO0VBQ0ksa0JBQWtCLEVBQUE7RUFHdEI7RUFDSTtJQUNJLGFBQWEsRUFBQTtFQUVqQjtJQUNJLGlCQUFpQixFQUFBLEVBQ3BCO0VBR0w7RUFDSTtJQUNJLFVBQVU7SUFDVixpQkFBZ0IsRUFBQSxFQUNuQiIsImZpbGUiOiJzcmMvYXBwL2FkbWluL2FkbWluLWRhc2hib2FyZC5jb21wb25lbnQuc2NzcyIsInNvdXJjZXNDb250ZW50IjpbIi5hdC1uYXYtYnV0dG9uc3tcbiAgICBwYWRkaW5nOiAyMHB4IDA7XG4gICAgdGV4dC1hbGlnbjogY2VudGVyO1xuICAgIFxuICAgIC5hdC1iYWNrLWJ0biwgLmF0LWNyZWF0ZS1idG57XG4gICAgICAgIGJ1dHRvbntcbiAgICAgICAgICAgIHdpZHRoOiAxNzBweDtcbiAgICAgICAgICAgICY6aG92ZXJ7XG4gICAgICAgICAgICAgICAgYm94LXNoYWRvdzogMHB4IDBweCAxMHB4ICM3Nzc7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG4gICAgQG1lZGlhIG9ubHkgc2NyZWVuIGFuZCAobWluLXdpZHRoOiA1NzZweCl7XG4gICAgICAgIC5hdC1iYWNrLWJ0bntcbiAgICAgICAgICAgIHRleHQtYWxpZ246IHJpZ2h0O1xuICAgICAgICB9XG4gICAgICAgIC5hdC1jcmVhdGUtYnRue1xuICAgICAgICAgICAgdGV4dC1hbGlnbjogbGVmdDtcbiAgICAgICAgfVxuICAgIH1cbn1cbi5hZG1pbi1kYXNoYm9hcmR7XG4gICAgLnVzZXItbGlzdHtcbiAgICAgICAgbWFyZ2luLXRvcDogNDBweDtcbiAgICB9XG59XG4uYXQtdXNlci1ib3h7XG4gICAgbWFyZ2luLWJvdHRvbTogMjBweDtcbiAgICBjdXJzb3I6IHBvaW50ZXI7XG4gICAgJjpob3ZlcntcbiAgICAgICAgYm94LXNoYWRvdzogMHB4IDBweCAxMHB4ICM3Nzc7XG4gICAgfVxufVxuLmZhLXVzZXJ7XG4gICAgZm9udC1zaXplOiA0MHB4O1xuICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTtcbiAgICBsaW5lLWhlaWdodDogNDBweDtcbn1cbi5hdC1lbGxpcHNpc3tcbmxpbmUtaGVpZ2h0OiA0MHB4O1xufVxuaXtcbiAgICBjb2xvcjogIzAwN2JmZjsgIFxufVxuLmZhLWVudmVsb3BlLCAuZmEtcGhvbmUtc3F1YXJle1xuICAgIG1hcmdpbi1yaWdodDogMTBweDtcbn1cblxuQG1lZGlhIG9ubHkgc2NyZWVuIGFuZCAobWF4LXdpZHRoOiAxMDIzcHgpe1xuICAgIC51c2VyLWljb257XG4gICAgICAgIGRpc3BsYXk6IG5vbmU7XG4gICAgfVxuICAgIC5hdC1lbWFpbCwgLmF0LW1vYmlsZXtcbiAgICAgICAgbGluZS1oZWlnaHQ6IDQwcHg7XG4gICAgfVxufVxuXG5AbWVkaWEgb25seSBzY3JlZW4gYW5kIChtYXgtd2lkdGg6IDU3NXB4KXtcbiAgICAuc2hhZG93LWJveC1jYXJke1xuICAgICAgICB3aWR0aDogOTAlO1xuICAgICAgICBtYXJnaW46MjBweCBhdXRvO1xuICAgIH1cbn1cbiJdfQ== */"

/***/ }),

/***/ "./src/app/admin/admin-dashboard.component.ts":
/*!****************************************************!*\
  !*** ./src/app/admin/admin-dashboard.component.ts ***!
  \****************************************************/
/*! exports provided: AdminDashboardComponent */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AdminDashboardComponent", function() { return AdminDashboardComponent; });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tslib */ "./node_modules/tslib/tslib.es6.js");
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");
/* harmony import */ var _services_app_service__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../services/app.service */ "./src/app/services/app.service.ts");
/* harmony import */ var ngx_toastr__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ngx-toastr */ "./node_modules/ngx-toastr/fesm5/ngx-toastr.js");
/* harmony import */ var _services_socket_service__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../services/socket.service */ "./src/app/services/socket.service.ts");
/* harmony import */ var ng2_cookies__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ng2-cookies */ "./node_modules/ng2-cookies/index.js");
/* harmony import */ var ng2_cookies__WEBPACK_IMPORTED_MODULE_6___default = /*#__PURE__*/__webpack_require__.n(ng2_cookies__WEBPACK_IMPORTED_MODULE_6__);
/* harmony import */ var ngx_bootstrap_modal__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ngx-bootstrap/modal */ "./node_modules/ngx-bootstrap/modal/fesm5/ngx-bootstrap-modal.js");








var AdminDashboardComponent = /** @class */ (function () {
    function AdminDashboardComponent(router, appService, toastr, socketService, modalService) {
        this.router = router;
        this.appService = appService;
        this.toastr = toastr;
        this.socketService = socketService;
        this.modalService = modalService;
        this.meetings = [];
        this.showUserList = true;
        this.showCalender = false;
        this.isEditMeeting = false;
        this.events = [];
        this.isReminderSnooze = true;
        this.isLoading = true;
    }
    AdminDashboardComponent.prototype.ngOnInit = function () {
        var _this = this;
        this.inviter = ng2_cookies__WEBPACK_IMPORTED_MODULE_6__["Cookie"].get('activeUserId');
        this.authToken = ng2_cookies__WEBPACK_IMPORTED_MODULE_6__["Cookie"].get('authToken');
        this.isAdmin = ng2_cookies__WEBPACK_IMPORTED_MODULE_6__["Cookie"].get('activeUserType') === 'admin';
        // check authToken, if not found then redirect to login page
        if (ng2_cookies__WEBPACK_IMPORTED_MODULE_6__["Cookie"].get('authToken') == null || ng2_cookies__WEBPACK_IMPORTED_MODULE_6__["Cookie"].get('authToken') == '' || ng2_cookies__WEBPACK_IMPORTED_MODULE_6__["Cookie"].get('authToken') == undefined) {
            if (this.meetingModalRef) {
                this.meetingModalRef.hide();
            }
            if (this.remiderModalRef) {
                this.remiderModalRef.hide();
            }
            this.isLoading = false;
            this.router.navigate(['']);
        }
        if (this.isAdmin) {
            this.getAllUsers();
            this.getMeetingsByInviter();
        }
        else {
            this.isLoading = false;
            this.router.navigate(['']);
        }
        // meeting remider for every 5 second
        setInterval(function () {
            if (_this.meetingListForReminder) {
                _this.meetingReminder();
            }
        }, 5000);
    };
    AdminDashboardComponent.prototype.getAllUsers = function () {
        var _this = this;
        // private function to get list of all users and display on admin dashboard
        if (this.authToken) {
            this.appService.getUsers()
                .subscribe(function (response) {
                _this.isLoading = false;
                if (response.status === 200) {
                    var responseData = response.data;
                    _this.userList = [];
                    for (var i = 0; i < responseData.length; i++) {
                        var user = {
                            fullName: responseData[i].firstName + " " + responseData[i].lastName,
                            userName: responseData[i].userName,
                            email: responseData[i].email,
                            mobile: "+" + responseData[i].countryCode + " " + responseData[i].mobileNumber,
                            userId: responseData[i].userId,
                            isAdmin: responseData[i].isAdmin
                        };
                        _this.userList.push(user);
                        _this.userSortedList = _this.userList.sort(function (user1, user2) {
                            if (user1.fullName > user2.fullName) {
                                return 1;
                            }
                            if (user1.fullName < user2.fullName) {
                                return -1;
                            }
                            return 0;
                        });
                    }
                }
                else {
                    _this.toastr.error(response.message);
                }
            }, function (error) {
                _this.isLoading = false;
                _this.toastr.error('something went wrong');
            });
        }
        else {
            this.toastr.info('Something went wrong, please login again.');
            if (this.meetingModalRef) {
                this.meetingModalRef.hide();
            }
            if (this.remiderModalRef) {
                this.remiderModalRef.hide();
            }
            this.router.navigate(['']);
        }
    };
    AdminDashboardComponent.prototype.getMeetingsByInviter = function () {
        var _this = this;
        // get all meetings scheduled by active admin for reminder
        this.appService.getMeetingsByInviter()
            .subscribe(function (response) {
            if (response.status === 200) {
                _this.meetingListForReminder = response.data;
            }
            else {
                _this.toastr.error(response.message);
            }
        }, function (error) {
            _this.toastr.error('something went wrong');
        });
    };
    AdminDashboardComponent.prototype.displaySelectedUserMeetings = function (selectedUser, isFirstCall) {
        var _this = this;
        // function to get meeting of selected user by admin 
        this.isLoading = true;
        this.selectedUser = selectedUser;
        ng2_cookies__WEBPACK_IMPORTED_MODULE_6__["Cookie"].delete('selectedUserId');
        ng2_cookies__WEBPACK_IMPORTED_MODULE_6__["Cookie"].delete('selectedUserFullName');
        ng2_cookies__WEBPACK_IMPORTED_MODULE_6__["Cookie"].delete('selectedUserEmail');
        ng2_cookies__WEBPACK_IMPORTED_MODULE_6__["Cookie"].set('selectedUserId', selectedUser.userId);
        ng2_cookies__WEBPACK_IMPORTED_MODULE_6__["Cookie"].set('selectedUserFullName', selectedUser.fullName + " (" + selectedUser.userName + ")");
        ng2_cookies__WEBPACK_IMPORTED_MODULE_6__["Cookie"].set('selectedUserEmail', selectedUser.email);
        this.appService.getSelectedUserMeetings(this.inviter, selectedUser.userId, this.authToken)
            .subscribe(function (data) {
            _this.isLoading = false;
            if (data.status === 200) {
                _this.meetings = data.data;
                for (var _i = 0, _a = _this.meetings; _i < _a.length; _i++) {
                    var event_1 = _a[_i];
                    event_1.title = event_1.title;
                    event_1.start = _this.getDateObject(event_1.start);
                    event_1.end = _this.getDateObject(event_1.end);
                    event_1.color = event_1.color;
                    event_1.actions = null;
                    event_1.remindMe = true;
                }
                _this.events = _this.meetings;
                if (isFirstCall) {
                    _this.toastr.success('meetings found for selected user');
                }
                _this.showCalender = true;
                _this.showUserList = false;
            }
            else {
                _this.toastr.error(data.message);
                _this.showCalender = true;
                _this.showUserList = false;
                _this.meetings = [];
            }
        }, function (error) {
            _this.isLoading = false;
            _this.toastr.error('something went wrong' + error);
            _this.showCalender = false;
            _this.showUserList = true;
            _this.meetings = [];
        });
    };
    AdminDashboardComponent.prototype.onCalendarEvent = function (calendarEvent) {
        var _this = this;
        this.calendarAction = calendarEvent.action;
        if (calendarEvent.action == 'create') {
            this.isEditMeeting = false;
            this.selectedDate = { start: calendarEvent.event.selectedDate, end: calendarEvent.event.selectedDate };
        }
        else if (calendarEvent.action == 'edit') {
            this.isEditMeeting = true;
            this.selectedMeeting = calendarEvent.event;
        }
        else if (calendarEvent.action == 'delete') {
            this.isLoading = true;
            this.appService.deleteMeeting(calendarEvent.event.meetingId)
                .subscribe(function (apiResponse) {
                _this.isLoading = false;
                if (apiResponse.status === 200) {
                    _this.toastr.success('Meeting deleted');
                    var meetingNotification = {
                        message: "Meeting Canceled. Your meeting with title: \"" + calendarEvent.event.title + "\" on " + calendarEvent.event.start + " has been cancled.",
                        userId: calendarEvent.event.invitee
                    };
                    _this.socketService.notifyUpdates(meetingNotification);
                }
                else {
                    _this.isLoading = false;
                    _this.toastr.error(apiResponse.message);
                }
            }, function (error) {
                _this.isLoading = false;
                _this.toastr.error('Error: something went wrong');
            });
        }
        if (calendarEvent.action == 'create' || calendarEvent.action == 'edit') {
            this.meetingModalRef = this.modalService.show(this.meetingTemplate, { class: 'modal-md' });
        }
    };
    AdminDashboardComponent.prototype.getDateObject = function (date) {
        // private function takes date as argument and returns date in UTC format
        return new Date(new Date(date).getUTCFullYear(), new Date(date).getUTCMonth(), new Date(date).getUTCDate(), new Date(date).getUTCHours(), new Date(date).getUTCMinutes());
    };
    AdminDashboardComponent.prototype.onCreateMeetingClicked = function () {
        // function called whrn create new meeting button clicked to disply modal fro meeting
        this.calendarAction = "create";
        this.selectedDate = { start: new Date(), end: new Date() };
        this.meetingModalRef = this.modalService.show(this.meetingTemplate, { class: 'modal-md' });
    };
    AdminDashboardComponent.prototype.closeMeetingModal = function () {
        // close the meeting form modal on click of close
        this.displaySelectedUserMeetings(this.selectedUser, false);
        this.meetingModalRef.hide();
    };
    AdminDashboardComponent.prototype.meetingReminder = function () {
        // function called for meeting reminder
        var currentTime = new Date().getTime();
        for (var _i = 0, _a = this.meetingListForReminder; _i < _a.length; _i++) {
            var meeting = _a[_i];
            var meetingTime = (this.getDateObject(meeting.start)).getTime();
            var timeDifference = meetingTime - currentTime;
            if (timeDifference <= 60000 && timeDifference > 0) {
                if ((this.isReminderSnooze || this.meetingEvent != meeting) && ng2_cookies__WEBPACK_IMPORTED_MODULE_6__["Cookie"].get('authToken')) {
                    this.isReminderSnooze = false;
                    this.meetingEvent = meeting;
                    this.remiderModalRef = this.modalService.show(this.reminderTemplate);
                    break;
                }
            }
            else if (meetingTime == currentTime && ng2_cookies__WEBPACK_IMPORTED_MODULE_6__["Cookie"].get('authToken')) {
                this.toastr.info('Meeting started');
            }
        }
    };
    AdminDashboardComponent.prototype.snoozeRemiderModal = function () {
        // funtion called when meeting reminder snoozed
        this.isReminderSnooze = true;
        this.remiderModalRef.hide();
    };
    AdminDashboardComponent.prototype.dismissRemiderModal = function () {
        // funtion called when meeting reminder dismissed
        this.remiderModalRef.hide();
    };
    AdminDashboardComponent.prototype.onClickBack = function () {
        // function called on click of back to user list button, get latest meetings for reminder by calling getMeetingsByInviter
        this.getMeetingsByInviter();
    };
    tslib__WEBPACK_IMPORTED_MODULE_0__["__decorate"]([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["ViewChild"])('meetingTemplate'),
        tslib__WEBPACK_IMPORTED_MODULE_0__["__metadata"]("design:type", _angular_core__WEBPACK_IMPORTED_MODULE_1__["TemplateRef"])
    ], AdminDashboardComponent.prototype, "meetingTemplate", void 0);
    tslib__WEBPACK_IMPORTED_MODULE_0__["__decorate"]([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["ViewChild"])('reminderTemplate'),
        tslib__WEBPACK_IMPORTED_MODULE_0__["__metadata"]("design:type", _angular_core__WEBPACK_IMPORTED_MODULE_1__["TemplateRef"])
    ], AdminDashboardComponent.prototype, "reminderTemplate", void 0);
    AdminDashboardComponent = tslib__WEBPACK_IMPORTED_MODULE_0__["__decorate"]([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["Component"])({
            selector: 'app-admin-dashboard',
            template: __webpack_require__(/*! ./admin-dashboard.component.html */ "./src/app/admin/admin-dashboard.component.html"),
            styles: [__webpack_require__(/*! ./admin-dashboard.component.scss */ "./src/app/admin/admin-dashboard.component.scss")]
        }),
        tslib__WEBPACK_IMPORTED_MODULE_0__["__metadata"]("design:paramtypes", [_angular_router__WEBPACK_IMPORTED_MODULE_2__["Router"],
            _services_app_service__WEBPACK_IMPORTED_MODULE_3__["AppService"],
            ngx_toastr__WEBPACK_IMPORTED_MODULE_4__["ToastrService"],
            _services_socket_service__WEBPACK_IMPORTED_MODULE_5__["SocketService"],
            ngx_bootstrap_modal__WEBPACK_IMPORTED_MODULE_7__["BsModalService"]])
    ], AdminDashboardComponent);
    return AdminDashboardComponent;
}());



/***/ }),

/***/ "./src/app/admin/admin.module.ts":
/*!***************************************!*\
  !*** ./src/app/admin/admin.module.ts ***!
  \***************************************/
/*! exports provided: AdminModule */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AdminModule", function() { return AdminModule; });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tslib */ "./node_modules/tslib/tslib.es6.js");
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _angular_common__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @angular/common */ "./node_modules/@angular/common/fesm5/common.js");
/* harmony import */ var _admin_dashboard_component__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./admin-dashboard.component */ "./src/app/admin/admin-dashboard.component.ts");
/* harmony import */ var _shared_shared_module__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../shared/shared.module */ "./src/app/shared/shared.module.ts");
/* harmony import */ var _angular_forms__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! @angular/forms */ "./node_modules/@angular/forms/fesm5/forms.js");
/* harmony import */ var ng_pick_datetime__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ng-pick-datetime */ "./node_modules/ng-pick-datetime/picker.js");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");








var AdminModule = /** @class */ (function () {
    function AdminModule() {
    }
    AdminModule = tslib__WEBPACK_IMPORTED_MODULE_0__["__decorate"]([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["NgModule"])({
            declarations: [_admin_dashboard_component__WEBPACK_IMPORTED_MODULE_3__["AdminDashboardComponent"]],
            imports: [
                _angular_common__WEBPACK_IMPORTED_MODULE_2__["CommonModule"],
                _shared_shared_module__WEBPACK_IMPORTED_MODULE_4__["SharedModule"],
                _angular_forms__WEBPACK_IMPORTED_MODULE_5__["FormsModule"],
                ng_pick_datetime__WEBPACK_IMPORTED_MODULE_6__["OwlDateTimeModule"],
                ng_pick_datetime__WEBPACK_IMPORTED_MODULE_6__["OwlNativeDateTimeModule"],
                _angular_forms__WEBPACK_IMPORTED_MODULE_5__["ReactiveFormsModule"],
                _angular_router__WEBPACK_IMPORTED_MODULE_7__["RouterModule"].forChild([{ path: '', component: _admin_dashboard_component__WEBPACK_IMPORTED_MODULE_3__["AdminDashboardComponent"] }])
            ]
        })
    ], AdminModule);
    return AdminModule;
}());



/***/ })

}]);
//# sourceMappingURL=admin-admin-module.js.map