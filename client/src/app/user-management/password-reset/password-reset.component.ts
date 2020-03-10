import { Component, OnInit, Input } from '@angular/core';
import { Router } from '@angular/router';
import { AppService } from 'src/app/services/app.service';
import { ToastrService } from 'ngx-toastr';

@Component({
  selector: 'app-password-reset',
  templateUrl: './password-reset.component.html',
  styleUrls: ['./password-reset.component.scss']
})
export class PasswordResetComponent implements OnInit {

  public password: string
  public confirmPassword: string
  public email: string;
  @Input() userId: string;
  
  constructor(private router: Router, 
    private appService: AppService, 
    private toastr: ToastrService) { }

  ngOnInit() {
  }

  public resetPassword(): void {
    if (this.password === this.confirmPassword) {
      let data={
        userId:this.userId,
        password:this.password,
        email:this.email
      }
      this.appService.resetPassword(data).subscribe((response) => {
        if (response.status === 200) {
          this.toastr.success('password changed successfully');
          this.router.navigate(['']);
        } else {
          this.toastr.error(response.message);
        }
      }, (err) => {
        this.toastr.error(err.message)
      })
    }else{
      this.toastr.warning('password not matched with confirmed password');
    }
  }
}
