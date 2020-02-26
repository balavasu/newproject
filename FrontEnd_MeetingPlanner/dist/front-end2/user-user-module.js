(window["webpackJsonp"] = window["webpackJsonp"] || []).push([["user-user-module"],{

/***/ "./src/app/user/user-dashboard.component.html":
/*!****************************************************!*\
  !*** ./src/app/user/user-dashboard.component.html ***!
  \****************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "<app-loader *ngIf=\"isLoading\"></app-loader>\n<app-header></app-header>\n<div class=\"container\">\n  <div class=\"row user-dashboard\">\n    <div class=\"col-12\">\n      <app-calendar [modalData]=\"modalData\" [meetings]=\"meetings\" (calendarEventEmitter)=\"onCalendarEvent($event)\">\n      </app-calendar>\n    </div>\n  </div>\n</div>\n\n<!-- template for meeting modal -->\n<ng-template #meetingTemplate>\n  <div class=\"modal-header\">\n    <h4 class=\"modal-title pull-left\"> Your meeting </h4>\n    <button type=\"button\" class=\"close pull-right\" aria-label=\"Close\" (click)=\"meetingModalRef.hide()\">\n      <span aria-hidden=\"true\">&times;</span>\n    </button>\n  </div>\n  <div class=\"modal-body\">\n    <app-meeting [isEditMeeting]=\"false\" [isViewOnlyMeeting]=\"true\" [selectedMeeting]=\"selectedMeetingForView\"\n      (onFormClose)=\"closeModal()\">\n    </app-meeting>\n  </div>\n</ng-template>\n\n<!-- template for reminder modal -->\n<ng-template #reminderTemplate let-close=\"close\">\n    <div class=\"modal-header\">\n      <h5 class=\"modal-title\">Meeting Reminder</h5>\n      <button type=\"button\" class=\"close\" (click)=\"snoozeRemiderModal()\">\n        <span aria-hidden=\"true\">&times;</span>\n      </button>\n    </div>\n    <div class=\"modal-body\">\n      <h6 class=\"card-title\">Your meeting <span><b>\"{{meetingEvent.title}}\"</b></span> will start soon.</h6>\n    </div>\n    <div class=\"modal-footer\">\n      <button type=\"button\" class=\"btn btn-outline-success\"\n        (click)=\"snoozeRemiderModal()\">Snooze</button>\n      <button type=\"button\" class=\"btn btn-outline-secondary\"\n        (click)=\"dismissRemiderModal()\">Dismiss</button>\n    </div>\n  </ng-template>"

/***/ }),

/***/ "./src/app/user/user-dashboard.component.scss":
/*!****************************************************!*\
  !*** ./src/app/user/user-dashboard.component.scss ***!
  \****************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = ".user-dashboard {\n  margin-top: 30px; }\n\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9hcHAvdXNlci9DOlxcVXNlcnNcXERFTExcXG5ld1xcTWVhbi1zdGFjay1hcHAxLW1lZXRpbmctcGxhbm5lci1tYXN0ZXJcXEZyb250RW5kX01lZXRpbmdQbGFubmVyL3NyY1xcYXBwXFx1c2VyXFx1c2VyLWRhc2hib2FyZC5jb21wb25lbnQuc2NzcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTtFQUNJLGdCQUFnQixFQUFBIiwiZmlsZSI6InNyYy9hcHAvdXNlci91c2VyLWRhc2hib2FyZC5jb21wb25lbnQuc2NzcyIsInNvdXJjZXNDb250ZW50IjpbIi51c2VyLWRhc2hib2FyZHtcbiAgICBtYXJnaW4tdG9wOiAzMHB4O1xufSJdfQ== */"

/***/ }),

/***/ "./src/app/user/user-dashboard.component.ts":
/*!**************************************************!*\
  !*** ./src/app/user/user-dashboard.component.ts ***!
  \**************************************************/
/*! exports provided: UserDashboardComponent */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "UserDashboardComponent", function() { return UserDashboardComponent; });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tslib */ "./node_modules/tslib/tslib.es6.js");
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var ng2_cookies__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ng2-cookies */ "./node_modules/ng2-cookies/index.js");
/* harmony import */ var ng2_cookies__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(ng2_cookies__WEBPACK_IMPORTED_MODULE_2__);
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");
/* harmony import */ var _services_app_service__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../services/app.service */ "./src/app/services/app.service.ts");
/* harmony import */ var ngx_toastr__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ngx-toastr */ "./node_modules/ngx-toastr/fesm5/ngx-toastr.js");
/* harmony import */ var _services_socket_service__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../services/socket.service */ "./src/app/services/socket.service.ts");
/* harmony import */ var ngx_bootstrap_modal__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ngx-bootstrap/modal */ "./node_modules/ngx-bootstrap/modal/fesm5/ngx-bootstrap-modal.js");








var UserDashboardComponent = /** @class */ (function () {
    function UserDashboardComponent(router, appService, toastr, socketService, modalService) {
        this.router = router;
        this.appService = appService;
        this.toastr = toastr;
        this.socketService = socketService;
        this.modalService = modalService;
        this.meetings = [];
        this.events = [];
        this.isLoading = true;
        this.showMeetingDetails = false;
        this.isReminderSnooze = true;
    }
    UserDashboardComponent.prototype.ngOnInit = function () {
        var _this = this;
        this.authToken = ng2_cookies__WEBPACK_IMPORTED_MODULE_2__["Cookie"].get('authToken');
        this.isAdmin = ng2_cookies__WEBPACK_IMPORTED_MODULE_2__["Cookie"].get('activeUserType') === 'admin';
        if (ng2_cookies__WEBPACK_IMPORTED_MODULE_2__["Cookie"].get('authToken') == null || ng2_cookies__WEBPACK_IMPORTED_MODULE_2__["Cookie"].get('authToken') == '' || ng2_cookies__WEBPACK_IMPORTED_MODULE_2__["Cookie"].get('authToken') == undefined) {
            if (this.meetingModalRef) {
                this.meetingModalRef.hide();
            }
            if (this.remiderModalRef) {
                this.remiderModalRef.hide();
            }
            this.router.navigate(['']);
        }
        if (this.isAdmin === false) {
            this.getMeetings();
        }
        else {
            this.router.navigate(['']);
        }
        // remider every 5 second
        setInterval(function () {
            _this.meetingReminder();
        }, 5000);
    };
    UserDashboardComponent.prototype.getMeetings = function () {
        var _this = this;
        // function call on page-load to get meetings to display in calender view.
        this.appService.getMeetingsByInvitee()
            .subscribe(function (response) {
            _this.isLoading = false;
            if (response.status == 200) {
                _this.meetings = response.data;
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
                _this.toastr.success('meetings found for you');
            }
            else {
                _this.toastr.error(response.message);
                _this.meetings = [];
            }
        }, function (error) {
            _this.isLoading = false;
            _this.toastr.error('something went wrong' + error);
            _this.meetings = [];
        });
    };
    UserDashboardComponent.prototype.onCalendarEvent = function (calendarEvent) {
        var _this = this;
        // function called when user click to view meeting details
        if (calendarEvent.action == 'view') {
            this.isLoading = true;
            this.showMeetingDetails = true;
            this.selectedMeetingForView = calendarEvent.event;
            this.appService.getUserById(calendarEvent.event.inviter)
                .subscribe(function (response) {
                _this.isLoading = false;
                if (response.status == 200) {
                    _this.selectedMeetingForView['inviterFullName'] = response.data.firstName + " " + response.data.lastName + " (" + response.data.userName + ")";
                    _this.meetingModalRef = _this.modalService.show(_this.meetingTemplate);
                }
                else {
                    _this.toastr.error(response.message);
                }
            }, function (error) {
                _this.isLoading = false;
                _this.toastr.error('something went wrong' + error);
            });
        }
    };
    UserDashboardComponent.prototype.closeModal = function () {
        // function to close the meeting modal
        this.getMeetings();
        this.meetingModalRef.hide();
    };
    UserDashboardComponent.prototype.meetingReminder = function () {
        // function called for meeting reminder
        var currentTime = new Date().getTime();
        for (var _i = 0, _a = this.meetings; _i < _a.length; _i++) {
            var meeting = _a[_i];
            var timeDifference = (meeting.start).getTime() - currentTime;
            if (timeDifference <= 60000 && timeDifference > 0) {
                if ((this.isReminderSnooze || this.meetingEvent != meeting) && ng2_cookies__WEBPACK_IMPORTED_MODULE_2__["Cookie"].get('authToken') != null) {
                    this.isReminderSnooze = false;
                    this.meetingEvent = meeting;
                    this.remiderModalRef = this.modalService.show(this.reminderTemplate);
                    break;
                }
            }
            else if ((meeting.start).getTime() == currentTime && ng2_cookies__WEBPACK_IMPORTED_MODULE_2__["Cookie"].get('authToken') != null) {
                this.toastr.info('Meeting started');
            }
        }
    };
    UserDashboardComponent.prototype.snoozeRemiderModal = function () {
        // funtion called when meeting reminder snoozed
        this.isReminderSnooze = true;
        this.remiderModalRef.hide();
    };
    UserDashboardComponent.prototype.dismissRemiderModal = function () {
        // funtion called when meeting reminder dismissed
        this.remiderModalRef.hide();
    };
    UserDashboardComponent.prototype.getDateObject = function (date) {
        return new Date(new Date(date).getUTCFullYear(), new Date(date).getUTCMonth(), new Date(date).getUTCDate(), new Date(date).getUTCHours(), new Date(date).getUTCMinutes());
    };
    tslib__WEBPACK_IMPORTED_MODULE_0__["__decorate"]([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["ViewChild"])('meetingTemplate'),
        tslib__WEBPACK_IMPORTED_MODULE_0__["__metadata"]("design:type", _angular_core__WEBPACK_IMPORTED_MODULE_1__["TemplateRef"])
    ], UserDashboardComponent.prototype, "meetingTemplate", void 0);
    tslib__WEBPACK_IMPORTED_MODULE_0__["__decorate"]([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["ViewChild"])('reminderTemplate'),
        tslib__WEBPACK_IMPORTED_MODULE_0__["__metadata"]("design:type", _angular_core__WEBPACK_IMPORTED_MODULE_1__["TemplateRef"])
    ], UserDashboardComponent.prototype, "reminderTemplate", void 0);
    UserDashboardComponent = tslib__WEBPACK_IMPORTED_MODULE_0__["__decorate"]([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["Component"])({
            selector: 'app-user-dashboard',
            template: __webpack_require__(/*! ./user-dashboard.component.html */ "./src/app/user/user-dashboard.component.html"),
            styles: [__webpack_require__(/*! ./user-dashboard.component.scss */ "./src/app/user/user-dashboard.component.scss")]
        }),
        tslib__WEBPACK_IMPORTED_MODULE_0__["__metadata"]("design:paramtypes", [_angular_router__WEBPACK_IMPORTED_MODULE_3__["Router"],
            _services_app_service__WEBPACK_IMPORTED_MODULE_4__["AppService"],
            ngx_toastr__WEBPACK_IMPORTED_MODULE_5__["ToastrService"],
            _services_socket_service__WEBPACK_IMPORTED_MODULE_6__["SocketService"],
            ngx_bootstrap_modal__WEBPACK_IMPORTED_MODULE_7__["BsModalService"]])
    ], UserDashboardComponent);
    return UserDashboardComponent;
}());



/***/ }),

/***/ "./src/app/user/user.module.ts":
/*!*************************************!*\
  !*** ./src/app/user/user.module.ts ***!
  \*************************************/
/*! exports provided: UserModule */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "UserModule", function() { return UserModule; });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tslib */ "./node_modules/tslib/tslib.es6.js");
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _angular_common__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @angular/common */ "./node_modules/@angular/common/fesm5/common.js");
/* harmony import */ var _user_dashboard_component__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./user-dashboard.component */ "./src/app/user/user-dashboard.component.ts");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");
/* harmony import */ var _shared_shared_module__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../shared/shared.module */ "./src/app/shared/shared.module.ts");






var UserModule = /** @class */ (function () {
    function UserModule() {
    }
    UserModule = tslib__WEBPACK_IMPORTED_MODULE_0__["__decorate"]([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["NgModule"])({
            declarations: [_user_dashboard_component__WEBPACK_IMPORTED_MODULE_3__["UserDashboardComponent"]],
            imports: [
                _angular_common__WEBPACK_IMPORTED_MODULE_2__["CommonModule"],
                _shared_shared_module__WEBPACK_IMPORTED_MODULE_5__["SharedModule"],
                _angular_router__WEBPACK_IMPORTED_MODULE_4__["RouterModule"].forChild([{ path: '', component: _user_dashboard_component__WEBPACK_IMPORTED_MODULE_3__["UserDashboardComponent"] }])
            ]
        })
    ], UserModule);
    return UserModule;
}());



/***/ })

}]);
//# sourceMappingURL=user-user-module.js.map