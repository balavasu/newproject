(window["webpackJsonp"] = window["webpackJsonp"] || []).push([["user-management-user-management-module"],{

/***/ "./src/app/user-management/forgot-password/forgot-password.component.html":
/*!********************************************************************************!*\
  !*** ./src/app/user-management/forgot-password/forgot-password.component.html ***!
  \********************************************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "<div class=\"row\">\n  <div class=\"col-sm-2\"></div>\n    <div class=\"col-xs-12 col-sm-10 shadow-box-card\">\n      <h2>Send reset link to email</h2>\n      <label for=\"inputEmail\">Email</label>\n      <input type=\"email\" id=\"FPEmail\" class=\"form-control\" [(ngModel)]=\"email\" placeholder=\"Enter email address\" required\n        autofocus>\n      <button class=\"btn btn-lg btn-block btn-primary\" type=\"button\" (click)=\"forgotPassword()\">Send</button>\n    </div>\n  </div>"

/***/ }),

/***/ "./src/app/user-management/forgot-password/forgot-password.component.scss":
/*!********************************************************************************!*\
  !*** ./src/app/user-management/forgot-password/forgot-password.component.scss ***!
  \********************************************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "input {\n  margin-bottom: 10px; }\n\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9hcHAvdXNlci1tYW5hZ2VtZW50L2ZvcmdvdC1wYXNzd29yZC9DOlxcVXNlcnNcXERFTExcXG5ld1xcTWVhbi1zdGFjay1hcHAxLW1lZXRpbmctcGxhbm5lci1tYXN0ZXJcXEZyb250RW5kX01lZXRpbmdQbGFubmVyL3NyY1xcYXBwXFx1c2VyLW1hbmFnZW1lbnRcXGZvcmdvdC1wYXNzd29yZFxcZm9yZ290LXBhc3N3b3JkLmNvbXBvbmVudC5zY3NzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBO0VBQ0ksbUJBQW1CLEVBQUEiLCJmaWxlIjoic3JjL2FwcC91c2VyLW1hbmFnZW1lbnQvZm9yZ290LXBhc3N3b3JkL2ZvcmdvdC1wYXNzd29yZC5jb21wb25lbnQuc2NzcyIsInNvdXJjZXNDb250ZW50IjpbImlucHV0e1xuICAgIG1hcmdpbi1ib3R0b206IDEwcHg7XG59Il19 */"

/***/ }),

/***/ "./src/app/user-management/forgot-password/forgot-password.component.ts":
/*!******************************************************************************!*\
  !*** ./src/app/user-management/forgot-password/forgot-password.component.ts ***!
  \******************************************************************************/
/*! exports provided: ForgotPasswordComponent */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "ForgotPasswordComponent", function() { return ForgotPasswordComponent; });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tslib */ "./node_modules/tslib/tslib.es6.js");
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var ngx_toastr__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ngx-toastr */ "./node_modules/ngx-toastr/fesm5/ngx-toastr.js");
/* harmony import */ var src_app_services_app_service__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! src/app/services/app.service */ "./src/app/services/app.service.ts");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");





var ForgotPasswordComponent = /** @class */ (function () {
    function ForgotPasswordComponent(appService, router, toastr) {
        this.appService = appService;
        this.router = router;
        this.toastr = toastr;
    }
    ForgotPasswordComponent.prototype.ngOnInit = function () {
    };
    ForgotPasswordComponent.prototype.forgotPassword = function () {
        var _this = this;
        if (!this.email) {
            this.toastr.warning('email required');
        }
        else {
            var data = {
                email: this.email
            };
            this.appService.forgotPassword(data)
                .subscribe(function (response) {
                _this.toastr.success('Please check your email to reset password');
                if (response.status === 200) {
                    setTimeout(function () {
                        _this.router.navigate(['']);
                    }, 1000);
                }
                else {
                    _this.toastr.error(response.message);
                }
            }, function (error) {
                _this.toastr.error('Something went wrong, please try again');
            });
        }
    };
    ForgotPasswordComponent = tslib__WEBPACK_IMPORTED_MODULE_0__["__decorate"]([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["Component"])({
            selector: 'app-forgot-password',
            template: __webpack_require__(/*! ./forgot-password.component.html */ "./src/app/user-management/forgot-password/forgot-password.component.html"),
            styles: [__webpack_require__(/*! ./forgot-password.component.scss */ "./src/app/user-management/forgot-password/forgot-password.component.scss")]
        }),
        tslib__WEBPACK_IMPORTED_MODULE_0__["__metadata"]("design:paramtypes", [src_app_services_app_service__WEBPACK_IMPORTED_MODULE_3__["AppService"],
            _angular_router__WEBPACK_IMPORTED_MODULE_4__["Router"],
            ngx_toastr__WEBPACK_IMPORTED_MODULE_2__["ToastrService"]])
    ], ForgotPasswordComponent);
    return ForgotPasswordComponent;
}());



/***/ }),

/***/ "./src/app/user-management/login/login.component.html":
/*!************************************************************!*\
  !*** ./src/app/user-management/login/login.component.html ***!
  \************************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "<div class=\"row\">\n  <div class=\"col-sm-2\"></div>\n  <div class=\"col-xs-12 col-sm-10 shadow-box-card\">\n    <h2>Login</h2>\n    <label>Email</label>\n    <input type=\"email\" id=\"loginEmail\" class=\"form-control\" [(ngModel)]=\"email\" placeholder=\"Enter email address\" required>\n    <label>Password</label>\n    <input type=\"password\" id=\"loginPassword\" class=\"form-control\" [(ngModel)]=\"password\" placeholder=\"Enter password\"required>\n    <button class=\"btn btn-lg btn-primary btn-block\" type=\"button\" (click)=\"login()\">Sign in</button>\n  </div>\n</div>"

/***/ }),

/***/ "./src/app/user-management/login/login.component.scss":
/*!************************************************************!*\
  !*** ./src/app/user-management/login/login.component.scss ***!
  \************************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "input, button {\n  margin-bottom: 10px; }\n\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9hcHAvdXNlci1tYW5hZ2VtZW50L2xvZ2luL0M6XFxVc2Vyc1xcREVMTFxcbmV3XFxNZWFuLXN0YWNrLWFwcDEtbWVldGluZy1wbGFubmVyLW1hc3RlclxcRnJvbnRFbmRfTWVldGluZ1BsYW5uZXIvc3JjXFxhcHBcXHVzZXItbWFuYWdlbWVudFxcbG9naW5cXGxvZ2luLmNvbXBvbmVudC5zY3NzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBO0VBQ0ksbUJBQW1CLEVBQUEiLCJmaWxlIjoic3JjL2FwcC91c2VyLW1hbmFnZW1lbnQvbG9naW4vbG9naW4uY29tcG9uZW50LnNjc3MiLCJzb3VyY2VzQ29udGVudCI6WyJpbnB1dCwgYnV0dG9ue1xuICAgIG1hcmdpbi1ib3R0b206IDEwcHg7XG59XG4iXX0= */"

/***/ }),

/***/ "./src/app/user-management/login/login.component.ts":
/*!**********************************************************!*\
  !*** ./src/app/user-management/login/login.component.ts ***!
  \**********************************************************/
/*! exports provided: LoginComponent */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "LoginComponent", function() { return LoginComponent; });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tslib */ "./node_modules/tslib/tslib.es6.js");
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _services_app_service__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../services/app.service */ "./src/app/services/app.service.ts");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");
/* harmony import */ var ngx_toastr__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ngx-toastr */ "./node_modules/ngx-toastr/fesm5/ngx-toastr.js");
/* harmony import */ var ng2_cookies__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ng2-cookies */ "./node_modules/ng2-cookies/index.js");
/* harmony import */ var ng2_cookies__WEBPACK_IMPORTED_MODULE_5___default = /*#__PURE__*/__webpack_require__.n(ng2_cookies__WEBPACK_IMPORTED_MODULE_5__);






var LoginComponent = /** @class */ (function () {
    function LoginComponent(appService, router, toastr) {
        var _this = this;
        this.appService = appService;
        this.router = router;
        this.toastr = toastr;
        this.login = function () {
            if (!_this.email) {
                _this.toastr.warning('email required');
            }
            else if (!_this.password) {
                _this.toastr.warning('password required');
            }
            else {
                var data = {
                    email: _this.email,
                    password: _this.password
                };
                _this.appService.onLogin(data)
                    .subscribe(function (apiResponse) {
                    if (apiResponse.status === 200) {
                        ng2_cookies__WEBPACK_IMPORTED_MODULE_5__["Cookie"].deleteAll();
                        var userType = apiResponse.data.userDetails.isAdmin ? 'admin' : 'user';
                        ng2_cookies__WEBPACK_IMPORTED_MODULE_5__["Cookie"].set('activeUserType', userType);
                        ng2_cookies__WEBPACK_IMPORTED_MODULE_5__["Cookie"].set('activeUserId', apiResponse.data.userDetails.userId);
                        ng2_cookies__WEBPACK_IMPORTED_MODULE_5__["Cookie"].set('activeUserEmail', apiResponse.data.userDetails.email);
                        ng2_cookies__WEBPACK_IMPORTED_MODULE_5__["Cookie"].set('activeUserName', apiResponse.data.userDetails.userName);
                        ng2_cookies__WEBPACK_IMPORTED_MODULE_5__["Cookie"].set('authToken', apiResponse.data.authToken);
                        ng2_cookies__WEBPACK_IMPORTED_MODULE_5__["Cookie"].set('activeUserFullName', apiResponse.data.userDetails.firstName + ' ' + apiResponse.data.userDetails.lastName);
                        if (apiResponse.data.userDetails.isAdmin) {
                            _this.router.navigate(['admin/dashboard']);
                        }
                        else {
                            _this.router.navigate(['user/dashboard']);
                        }
                    }
                    else {
                        _this.toastr.error('login failed, please try again');
                    }
                }, function (err) {
                    _this.toastr.error('login failed, please try again');
                });
            }
        };
    }
    LoginComponent.prototype.ngOnInit = function () {
    };
    LoginComponent = tslib__WEBPACK_IMPORTED_MODULE_0__["__decorate"]([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["Component"])({
            selector: 'app-login',
            template: __webpack_require__(/*! ./login.component.html */ "./src/app/user-management/login/login.component.html"),
            styles: [__webpack_require__(/*! ./login.component.scss */ "./src/app/user-management/login/login.component.scss")]
        }),
        tslib__WEBPACK_IMPORTED_MODULE_0__["__metadata"]("design:paramtypes", [_services_app_service__WEBPACK_IMPORTED_MODULE_2__["AppService"],
            _angular_router__WEBPACK_IMPORTED_MODULE_3__["Router"],
            ngx_toastr__WEBPACK_IMPORTED_MODULE_4__["ToastrService"]])
    ], LoginComponent);
    return LoginComponent;
}());



/***/ }),

/***/ "./src/app/user-management/password-reset/password-reset.component.html":
/*!******************************************************************************!*\
  !*** ./src/app/user-management/password-reset/password-reset.component.html ***!
  \******************************************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "<div class=\"row\">\n  <div class=\"col-md-3\"></div>\n  <div class=\"col-sm-12 col-md-6 shadow-box-card\">\n    <h2>Password reset</h2>\n    <label>Email</label>\n    <input type=\"text\" id=\"email\" class=\"form-control\" [(ngModel)]=\"email\" placeholder=\"Enter email address\" required>\n\n    <label>Password</label>\n    <input type=\"password\" id=\"Password\" class=\"form-control\" [(ngModel)]=\"password\" placeholder=\"Enter password\"\n      required>\n\n    <label>Confirm Password</label>\n    <input type=\"password\" id=\"confirmPassword\" class=\"form-control\" [(ngModel)]=\"confirmPassword\"\n      placeholder=\"Enter password again\" required>\n\n    <button class=\"btn btn-lg btn-primary btn-block\" type=\"button\" (click)=\"resetPassword()\">Reset Password</button>\n  </div>\n</div>"

/***/ }),

/***/ "./src/app/user-management/password-reset/password-reset.component.scss":
/*!******************************************************************************!*\
  !*** ./src/app/user-management/password-reset/password-reset.component.scss ***!
  \******************************************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "input {\n  margin-bottom: 10px; }\n\nbutton {\n  margin-top: 15px; }\n\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9hcHAvdXNlci1tYW5hZ2VtZW50L3Bhc3N3b3JkLXJlc2V0L0M6XFxVc2Vyc1xcREVMTFxcbmV3XFxNZWFuLXN0YWNrLWFwcDEtbWVldGluZy1wbGFubmVyLW1hc3RlclxcRnJvbnRFbmRfTWVldGluZ1BsYW5uZXIvc3JjXFxhcHBcXHVzZXItbWFuYWdlbWVudFxccGFzc3dvcmQtcmVzZXRcXHBhc3N3b3JkLXJlc2V0LmNvbXBvbmVudC5zY3NzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBO0VBQ0ksbUJBQW1CLEVBQUE7O0FBRXZCO0VBQ0ksZ0JBQWdCLEVBQUEiLCJmaWxlIjoic3JjL2FwcC91c2VyLW1hbmFnZW1lbnQvcGFzc3dvcmQtcmVzZXQvcGFzc3dvcmQtcmVzZXQuY29tcG9uZW50LnNjc3MiLCJzb3VyY2VzQ29udGVudCI6WyJpbnB1dHtcbiAgICBtYXJnaW4tYm90dG9tOiAxMHB4O1xufVxuYnV0dG9ue1xuICAgIG1hcmdpbi10b3A6IDE1cHg7XG59Il19 */"

/***/ }),

/***/ "./src/app/user-management/password-reset/password-reset.component.ts":
/*!****************************************************************************!*\
  !*** ./src/app/user-management/password-reset/password-reset.component.ts ***!
  \****************************************************************************/
/*! exports provided: PasswordResetComponent */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "PasswordResetComponent", function() { return PasswordResetComponent; });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tslib */ "./node_modules/tslib/tslib.es6.js");
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");
/* harmony import */ var src_app_services_app_service__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! src/app/services/app.service */ "./src/app/services/app.service.ts");
/* harmony import */ var ngx_toastr__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ngx-toastr */ "./node_modules/ngx-toastr/fesm5/ngx-toastr.js");





var PasswordResetComponent = /** @class */ (function () {
    function PasswordResetComponent(router, appService, toastr) {
        this.router = router;
        this.appService = appService;
        this.toastr = toastr;
    }
    PasswordResetComponent.prototype.ngOnInit = function () {
    };
    PasswordResetComponent.prototype.resetPassword = function () {
        var _this = this;
        if (this.password === this.confirmPassword) {
            var data = {
                userId: this.userId,
                password: this.password,
                email: this.email
            };
            this.appService.resetPassword(data).subscribe(function (response) {
                if (response.status === 200) {
                    _this.toastr.success('password changed successfully');
                    _this.router.navigate(['']);
                }
                else {
                    _this.toastr.error(response.message);
                }
            }, function (err) {
                _this.toastr.error(err.message);
            });
        }
        else {
            this.toastr.warning('password not matched with confirmed password');
        }
    };
    tslib__WEBPACK_IMPORTED_MODULE_0__["__decorate"]([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["Input"])(),
        tslib__WEBPACK_IMPORTED_MODULE_0__["__metadata"]("design:type", String)
    ], PasswordResetComponent.prototype, "userId", void 0);
    PasswordResetComponent = tslib__WEBPACK_IMPORTED_MODULE_0__["__decorate"]([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["Component"])({
            selector: 'app-password-reset',
            template: __webpack_require__(/*! ./password-reset.component.html */ "./src/app/user-management/password-reset/password-reset.component.html"),
            styles: [__webpack_require__(/*! ./password-reset.component.scss */ "./src/app/user-management/password-reset/password-reset.component.scss")]
        }),
        tslib__WEBPACK_IMPORTED_MODULE_0__["__metadata"]("design:paramtypes", [_angular_router__WEBPACK_IMPORTED_MODULE_2__["Router"],
            src_app_services_app_service__WEBPACK_IMPORTED_MODULE_3__["AppService"],
            ngx_toastr__WEBPACK_IMPORTED_MODULE_4__["ToastrService"]])
    ], PasswordResetComponent);
    return PasswordResetComponent;
}());



/***/ }),

/***/ "./src/app/user-management/signup/signup.component.html":
/*!**************************************************************!*\
  !*** ./src/app/user-management/signup/signup.component.html ***!
  \**************************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "<app-loader *ngIf=\"isLoading\"></app-loader>\n<h2>Sign Up</h2>\n<div class=\"row\">\n  <div class=\"col-12\">\n    <input type=\"checkbox\" class=\"admin-checkbox\" id=\"userType\" [(ngModel)]=\"isAdmin\" name=\"userType\" (change)=\"setUserName()\">Signup as an Admin\n\n    <br/>\n    <label>First Name</label>\n    <input type=\"text\" id=\"inputFirstName\" class=\"form-control\" [(ngModel)]=\"firstName\" placeholder=\"Enter first name\" required>\n    \n    <label>Last Name</label>\n    <input type=\"text\" id=\"inputLastName\" class=\"form-control\" [(ngModel)]=\"lastName\" placeholder=\"Enter last name\" required>\n    \n    <label>User Name</label>\n    <input type=\"text\" id=\"inputUserName\" class=\"form-control\" [(ngModel)]=\"userName\" placeholder=\"Enter user name\"\n      (focusout)=\"setUserName()\" required>\n\n      <label>Email</label>\n    <input type=\"email\" id=\"signUpEmail\" class=\"form-control\" [(ngModel)]=\"email\" placeholder=\"Enter email address\" required>\n\n    <label>Password</label>\n    <input type=\"password\" id=\"signupPassword\" class=\"form-control\" [(ngModel)]=\"password\" placeholder=\"Enter password - minimum 8 chracters length\" required>\n    \n    <label>Select Country</label>\n    <select class=\"form-control\" id=\"inputCountry\" [(ngModel)]=\"selectedCountry\" name=\"country\"\n      (change)=\"onCountryChange()\">\n      <option *ngFor=\"let country of countryList\" [value]=\"country.code\">{{country.name}}</option>\n    </select>\n\n    <label>Mobile</label>\n    <div class=\"input-group\">\n      <div class=\"input-group-text\">+{{countryCode}}</div>\n      <input type=\"number\" pattern=\"^\\d{10}$\" min=\"10\" id=\"inputMobile\" class=\"form-control\" name=\"mobile\"\n        #mobile=\"ngModel\" [(ngModel)]=\"mobileNumber\" placeholder=\"Enter 10 digit mobile number\" required>\n      <br>\n      <div [hidden]=\"mobile.valid || mobile.pristine\" class=\"alert alert-danger col-12\">\n        Mobile Number must be 10 numbers\n      </div>\n    </div>\n\n    <button class=\"btn btn-lg btn-primary btn-block\" type=\"button\" (click)=\"signUp()\">Sign Up</button>\n\n  </div>\n</div>"

/***/ }),

/***/ "./src/app/user-management/signup/signup.component.scss":
/*!**************************************************************!*\
  !*** ./src/app/user-management/signup/signup.component.scss ***!
  \**************************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "input, select {\n  margin-bottom: 10px; }\n\n.admin-checkbox {\n  margin-right: 10px; }\n\n.input-group {\n  margin-bottom: 15px; }\n\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9hcHAvdXNlci1tYW5hZ2VtZW50L3NpZ251cC9DOlxcVXNlcnNcXERFTExcXG5ld1xcTWVhbi1zdGFjay1hcHAxLW1lZXRpbmctcGxhbm5lci1tYXN0ZXJcXEZyb250RW5kX01lZXRpbmdQbGFubmVyL3NyY1xcYXBwXFx1c2VyLW1hbmFnZW1lbnRcXHNpZ251cFxcc2lnbnVwLmNvbXBvbmVudC5zY3NzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBO0VBQ0ksbUJBQW1CLEVBQUE7O0FBRXZCO0VBQ0ksa0JBQWtCLEVBQUE7O0FBRXRCO0VBQ0ksbUJBQW1CLEVBQUEiLCJmaWxlIjoic3JjL2FwcC91c2VyLW1hbmFnZW1lbnQvc2lnbnVwL3NpZ251cC5jb21wb25lbnQuc2NzcyIsInNvdXJjZXNDb250ZW50IjpbImlucHV0LCBzZWxlY3R7XG4gICAgbWFyZ2luLWJvdHRvbTogMTBweDtcbn1cbi5hZG1pbi1jaGVja2JveHtcbiAgICBtYXJnaW4tcmlnaHQ6IDEwcHg7XG59XG4uaW5wdXQtZ3JvdXB7XG4gICAgbWFyZ2luLWJvdHRvbTogMTVweDtcbn0iXX0= */"

/***/ }),

/***/ "./src/app/user-management/signup/signup.component.ts":
/*!************************************************************!*\
  !*** ./src/app/user-management/signup/signup.component.ts ***!
  \************************************************************/
/*! exports provided: SignupComponent */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "SignupComponent", function() { return SignupComponent; });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tslib */ "./node_modules/tslib/tslib.es6.js");
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _services_app_service__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../services/app.service */ "./src/app/services/app.service.ts");
/* harmony import */ var ngx_toastr__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ngx-toastr */ "./node_modules/ngx-toastr/fesm5/ngx-toastr.js");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");





var SignupComponent = /** @class */ (function () {
    function SignupComponent(appService, router, toastr) {
        var _this = this;
        this.appService = appService;
        this.router = router;
        this.toastr = toastr;
        this.userName = '';
        this.isAdmin = false;
        this.countryList = [];
        this.isLoading = false;
        this.signUp = function () {
            // validate signup form and call service method for api call of signup
            if (!_this.userName) {
                _this.toastr.warning('username required');
            }
            else if (!_this.firstName) {
                _this.toastr.warning('first name required');
            }
            else if (!_this.lastName) {
                _this.toastr.warning('last name required');
            }
            else if (!_this.mobileNumber) {
                _this.toastr.warning('mobile number required');
            }
            else if (!_this.email) {
                _this.toastr.warning('email id required');
            }
            else if (!_this.password) {
                _this.toastr.warning('password required');
            }
            else if (_this.mobileNumber.toString().length != 10) {
                _this.toastr.warning('Please enter 10 digit mobile number');
            }
            else {
                var data = {
                    firstName: _this.firstName,
                    lastName: _this.lastName,
                    mobileNumber: _this.mobileNumber,
                    email: _this.email,
                    password: _this.password,
                    userName: _this.userName,
                    isAdmin: _this.isAdmin,
                    countryName: _this.selectedCountry,
                    countryCode: _this.countryCode
                };
                _this.isLoading = true;
                _this.appService.signUp(data)
                    .subscribe(function (apiResponse) {
                    _this.isLoading = false;
                    if (apiResponse.status === 200) {
                        _this.toastr.success('Signup successful');
                        setTimeout(function () {
                            _this.router.navigate(['']);
                        }, 1000);
                    }
                    else {
                        _this.toastr.error(apiResponse.message);
                    }
                }, function (err) {
                    _this.isLoading = false;
                    _this.toastr.error('some error occured');
                });
            }
        };
    }
    SignupComponent.prototype.ngOnInit = function () {
        this.getCountries();
    };
    SignupComponent.prototype.getCountries = function () {
        var _this = this;
        // get list of countries 
        this.appService.getCountries()
            .subscribe(function (responseList) {
            for (var item in responseList) {
                _this.countryList.push({ code: item, name: responseList[item] });
            }
            _this.countryList = _this.countryList.sort(function (first, second) {
                return first.name.toUpperCase() < second.name.toUpperCase() ? -1 : (first.name.toUpperCase() > second.name.toUpperCase() ? 1 : 0);
            });
            _this.getCountryCodes();
            _this.selectedCountry = 'IN';
            _this.countryName = _this.countryList[_this.selectedCountry];
        });
    };
    SignupComponent.prototype.getCountryCodes = function () {
        var _this = this;
        // get list of country codes
        this.appService.getCountryCodes()
            .subscribe(function (data) {
            _this.countryCodes = data;
            _this.countryCode = _this.countryCodes['IN'];
        });
    };
    SignupComponent.prototype.onCountryChange = function () {
        // called when user change the country code
        this.countryCode = this.countryCodes[this.selectedCountry];
        this.countryName = this.countryList[this.selectedCountry];
    };
    SignupComponent.prototype.setUserName = function () {
        // if user singup as an admin then suffix the username with "-admin"
        if (this.isAdmin && this.userName !== '') {
            if (!this.userName.includes('-admin')) {
                this.userName = this.userName + '-admin';
            }
        }
        else {
            this.userName = this.userName.split('-admin')[0];
        }
    };
    SignupComponent = tslib__WEBPACK_IMPORTED_MODULE_0__["__decorate"]([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["Component"])({
            selector: 'app-signup',
            template: __webpack_require__(/*! ./signup.component.html */ "./src/app/user-management/signup/signup.component.html"),
            styles: [__webpack_require__(/*! ./signup.component.scss */ "./src/app/user-management/signup/signup.component.scss")]
        }),
        tslib__WEBPACK_IMPORTED_MODULE_0__["__metadata"]("design:paramtypes", [_services_app_service__WEBPACK_IMPORTED_MODULE_2__["AppService"],
            _angular_router__WEBPACK_IMPORTED_MODULE_4__["Router"],
            ngx_toastr__WEBPACK_IMPORTED_MODULE_3__["ToastrService"]])
    ], SignupComponent);
    return SignupComponent;
}());



/***/ }),

/***/ "./src/app/user-management/user-management.component.html":
/*!****************************************************************!*\
  !*** ./src/app/user-management/user-management.component.html ***!
  \****************************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = "<!-- LOADER -->\n<app-loader *ngIf=\"isLoading\"></app-loader>\n<!-- APP HEADER -->\n<app-header></app-header>\n<div class=\"container\">\n    <div *ngIf=\"isResetPassWord; then resetPassword else signupAndLogin\"></div>\n    <!-- PASSWORD RESET -->\n    <ng-template #resetPassword>\n        <div class=\"row\">\n            <div class=\"col-12\">\n                <app-password-reset [userId]=\"userId\"></app-password-reset>\n            </div>\n        </div>\n    </ng-template>\n    <ng-template #signupAndLogin>\n        <div class=\"row\"> \n            <div class=\"col-xs-12 col-sm-6 signup shadow-box-card\">\n                <!-- SIGN UP -->\n                <app-signup></app-signup>\n            </div>\n            <div class=\"col-xs-12 col-sm-6 login\">\n                <div *ngIf=\"isForgatePassword; then forgotPassword else login\"></div>\n                <ng-template #forgotPassword>\n                    <!-- FORGOT PASSWORD -->\n                    <app-forgot-password></app-forgot-password>\n                </ng-template>\n                <ng-template #login>\n                    <!-- LOGIN -->\n                    <app-login></app-login>\n                </ng-template>\n               <div class=\"row\">\n                   <div class=\"col-12 forgotPassword\">\n                        <a (click)=\"isForgatePassword=!isForgatePassword\">{{isForgatePassword? 'Back to Login' : 'Forgot Password?'}}</a>\n                   </div>\n               </div>\n            </div>\n        </div>\n    </ng-template>\n</div>"

/***/ }),

/***/ "./src/app/user-management/user-management.component.scss":
/*!****************************************************************!*\
  !*** ./src/app/user-management/user-management.component.scss ***!
  \****************************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

module.exports = ".container {\n  margin-top: 20px;\n  margin-bottom: 50px; }\n\n.forgotPassword {\n  text-align: right;\n  cursor: pointer;\n  color: #005cbf;\n  text-decoration: underline;\n  font-weight: 500;\n  margin-top: 15px; }\n\n@media only screen and (max-width: 575px) {\n  .signup, .login {\n    margin: 20px auto;\n    width: 90%; } }\n\n/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9hcHAvdXNlci1tYW5hZ2VtZW50L0M6XFxVc2Vyc1xcREVMTFxcbmV3XFxNZWFuLXN0YWNrLWFwcDEtbWVldGluZy1wbGFubmVyLW1hc3RlclxcRnJvbnRFbmRfTWVldGluZ1BsYW5uZXIvc3JjXFxhcHBcXHVzZXItbWFuYWdlbWVudFxcdXNlci1tYW5hZ2VtZW50LmNvbXBvbmVudC5zY3NzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBO0VBQ0ksZ0JBQWdCO0VBQ2hCLG1CQUFtQixFQUFBOztBQUV2QjtFQUNJLGlCQUFpQjtFQUNqQixlQUFlO0VBQ2YsY0FBYztFQUNkLDBCQUEwQjtFQUMxQixnQkFBZ0I7RUFDaEIsZ0JBQWdCLEVBQUE7O0FBR3BCO0VBQ0k7SUFDSSxpQkFBaUI7SUFDakIsVUFBVSxFQUFBLEVBQ2IiLCJmaWxlIjoic3JjL2FwcC91c2VyLW1hbmFnZW1lbnQvdXNlci1tYW5hZ2VtZW50LmNvbXBvbmVudC5zY3NzIiwic291cmNlc0NvbnRlbnQiOlsiLmNvbnRhaW5lcntcbiAgICBtYXJnaW4tdG9wOiAyMHB4O1xuICAgIG1hcmdpbi1ib3R0b206IDUwcHg7XG59XG4uZm9yZ290UGFzc3dvcmR7XG4gICAgdGV4dC1hbGlnbjogcmlnaHQ7XG4gICAgY3Vyc29yOiBwb2ludGVyO1xuICAgIGNvbG9yOiAjMDA1Y2JmO1xuICAgIHRleHQtZGVjb3JhdGlvbjogdW5kZXJsaW5lO1xuICAgIGZvbnQtd2VpZ2h0OiA1MDA7XG4gICAgbWFyZ2luLXRvcDogMTVweDtcbn1cblxuQG1lZGlhIG9ubHkgc2NyZWVuIGFuZCAobWF4LXdpZHRoOiA1NzVweCl7XG4gICAgLnNpZ251cCwgLmxvZ2lue1xuICAgICAgICBtYXJnaW46IDIwcHggYXV0bztcbiAgICAgICAgd2lkdGg6IDkwJTtcbiAgICB9XG59XG4iXX0= */"

/***/ }),

/***/ "./src/app/user-management/user-management.component.ts":
/*!**************************************************************!*\
  !*** ./src/app/user-management/user-management.component.ts ***!
  \**************************************************************/
/*! exports provided: UserManagementComponent */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "UserManagementComponent", function() { return UserManagementComponent; });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tslib */ "./node_modules/tslib/tslib.es6.js");
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");



var UserManagementComponent = /** @class */ (function () {
    function UserManagementComponent(router) {
        this.router = router;
        this.isResetPassWord = false;
        this.isForgatePassword = false;
        this.isLoading = true;
    }
    UserManagementComponent.prototype.ngOnInit = function () {
        // if route path is reset password then redirect to reset password page
        this.isLoading = false;
        var paramsArray = this.router.url.split('/resetPassword/');
        if (paramsArray.length == 2) {
            this.userId = paramsArray[1];
            this.isResetPassWord = true;
        }
        else {
            this.router.navigate(['']);
        }
    };
    UserManagementComponent = tslib__WEBPACK_IMPORTED_MODULE_0__["__decorate"]([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["Component"])({
            selector: 'app-user-management',
            template: __webpack_require__(/*! ./user-management.component.html */ "./src/app/user-management/user-management.component.html"),
            styles: [__webpack_require__(/*! ./user-management.component.scss */ "./src/app/user-management/user-management.component.scss")]
        }),
        tslib__WEBPACK_IMPORTED_MODULE_0__["__metadata"]("design:paramtypes", [_angular_router__WEBPACK_IMPORTED_MODULE_2__["Router"]])
    ], UserManagementComponent);
    return UserManagementComponent;
}());



/***/ }),

/***/ "./src/app/user-management/user-management.module.ts":
/*!***********************************************************!*\
  !*** ./src/app/user-management/user-management.module.ts ***!
  \***********************************************************/
/*! exports provided: UserManagementModule */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "UserManagementModule", function() { return UserManagementModule; });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tslib */ "./node_modules/tslib/tslib.es6.js");
/* harmony import */ var _angular_core__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @angular/core */ "./node_modules/@angular/core/fesm5/core.js");
/* harmony import */ var _angular_common__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @angular/common */ "./node_modules/@angular/common/fesm5/common.js");
/* harmony import */ var _login_login_component__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./login/login.component */ "./src/app/user-management/login/login.component.ts");
/* harmony import */ var _user_management_component__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./user-management.component */ "./src/app/user-management/user-management.component.ts");
/* harmony import */ var _signup_signup_component__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./signup/signup.component */ "./src/app/user-management/signup/signup.component.ts");
/* harmony import */ var _angular_forms__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! @angular/forms */ "./node_modules/@angular/forms/fesm5/forms.js");
/* harmony import */ var _angular_router__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! @angular/router */ "./node_modules/@angular/router/fesm5/router.js");
/* harmony import */ var _shared_shared_module__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../shared/shared.module */ "./src/app/shared/shared.module.ts");
/* harmony import */ var _forgot_password_forgot_password_component__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ./forgot-password/forgot-password.component */ "./src/app/user-management/forgot-password/forgot-password.component.ts");
/* harmony import */ var _password_reset_password_reset_component__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ./password-reset/password-reset.component */ "./src/app/user-management/password-reset/password-reset.component.ts");











var routes = [
    {
        path: '',
        children: [
            { path: 'resetPassword', component: _password_reset_password_reset_component__WEBPACK_IMPORTED_MODULE_10__["PasswordResetComponent"] },
            { path: '', component: _user_management_component__WEBPACK_IMPORTED_MODULE_4__["UserManagementComponent"] },
        ]
    }
];
var UserManagementModule = /** @class */ (function () {
    function UserManagementModule() {
    }
    UserManagementModule = tslib__WEBPACK_IMPORTED_MODULE_0__["__decorate"]([
        Object(_angular_core__WEBPACK_IMPORTED_MODULE_1__["NgModule"])({
            declarations: [_login_login_component__WEBPACK_IMPORTED_MODULE_3__["LoginComponent"], _user_management_component__WEBPACK_IMPORTED_MODULE_4__["UserManagementComponent"], _signup_signup_component__WEBPACK_IMPORTED_MODULE_5__["SignupComponent"], _forgot_password_forgot_password_component__WEBPACK_IMPORTED_MODULE_9__["ForgotPasswordComponent"], _password_reset_password_reset_component__WEBPACK_IMPORTED_MODULE_10__["PasswordResetComponent"]],
            imports: [
                _angular_common__WEBPACK_IMPORTED_MODULE_2__["CommonModule"],
                _angular_forms__WEBPACK_IMPORTED_MODULE_6__["FormsModule"],
                _shared_shared_module__WEBPACK_IMPORTED_MODULE_8__["SharedModule"],
                _angular_router__WEBPACK_IMPORTED_MODULE_7__["RouterModule"].forChild([{ path: '', component: _user_management_component__WEBPACK_IMPORTED_MODULE_4__["UserManagementComponent"] }])
            ]
        })
    ], UserManagementModule);
    return UserManagementModule;
}());



/***/ })

}]);
//# sourceMappingURL=user-management-user-management-module.js.map