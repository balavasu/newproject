import { Component, OnInit } from '@angular/core';
import { ToastrService } from 'ngx-toastr';
import { AppService } from 'src/app/services/app.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-forgot-password',
  templateUrl: './forgot-password.component.html',
  styleUrls: ['./forgot-password.component.scss']
})
export class ForgotPasswordComponent implements OnInit {

  public email: string;
  constructor(
    public appService: AppService,
    public router: Router,
     private toastr: ToastrService) { }

  ngOnInit() {
  }

  public forgotPassword(): void{
    if (!this.email) {
      this.toastr.warning('email required')
    } else {
      let data = {
        email: this.email
      };
      this.appService.forgotPassword(data)
        .subscribe((response) => {
          this.toastr.success('Please check your email to reset password')
          if (response.status === 200) {
            setTimeout(() => {
              this.router.navigate(['']);
            }, 1000)
          } else {
            this.toastr.error(response.message)
          }
        }, (error) => {
          this.toastr.error('Something went wrong, please try again')
        })
    }
  }

}
