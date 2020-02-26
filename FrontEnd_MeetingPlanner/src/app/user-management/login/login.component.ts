import { Component, OnInit } from '@angular/core';
import { AppService } from '../../services/app.service';
import { Router } from '@angular/router';
import { ToastrService } from 'ngx-toastr';
import { Cookie } from 'ng2-cookies';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {
  public email: string
  public password: string

  constructor(
    public appService: AppService,
    public router: Router,
    private toastr: ToastrService) { }

  ngOnInit() {
  }

  public login: any = () => {
    if (!this.email) {
      this.toastr.warning('email required');
    } else if (!this.password) {
      this.toastr.warning('password required');
    } else {
      let data = {
        email: this.email,
        password: this.password
      }
      this.appService.onLogin(data)
        .subscribe((apiResponse) => {
          if (apiResponse.status === 200) {
            Cookie.deleteAll();
            let userType = apiResponse.data.userDetails.isAdmin? 'admin':'user';
            Cookie.set('activeUserType', userType);
            Cookie.set('activeUserId', apiResponse.data.userDetails.userId);
            Cookie.set('activeUserEmail', apiResponse.data.userDetails.email);
            Cookie.set('activeUserName', apiResponse.data.userDetails.userName);
            Cookie.set('authToken', apiResponse.data.authToken);
            Cookie.set('activeUserFullName', apiResponse.data.userDetails.firstName + ' ' + apiResponse.data.userDetails.lastName);
            if(apiResponse.data.userDetails.isAdmin){
              this.router.navigate(['admin/dashboard']);
            }else{
              this.router.navigate(['user/dashboard']);
            }
          } else {
            this.toastr.error('login failed, please try again');
          }
        }, (err) => {
          this.toastr.error('login failed, please try again');
        });
    } 
  } 
}