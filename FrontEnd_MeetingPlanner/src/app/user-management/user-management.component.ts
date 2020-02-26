import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';

@Component({
  selector: 'app-user-management',
  templateUrl: './user-management.component.html',
  styleUrls: ['./user-management.component.scss']
})
export class UserManagementComponent implements OnInit {
  public isResetPassWord: boolean = false;
  public isForgatePassword: boolean = false;
  public currentUrl: string;
  public userId: string;
  public isLoading: boolean = true;

  constructor(
    private router: Router
  ) { }

  ngOnInit() {
    // if route path is reset password then redirect to reset password page
    this.isLoading = false;
    let paramsArray = this.router.url.split('/resetPassword/');
    if (paramsArray.length == 2) {
      this.userId = paramsArray[1];
      this.isResetPassWord = true;
    } else {
      this.router.navigate(['']);
    }
  }
}
