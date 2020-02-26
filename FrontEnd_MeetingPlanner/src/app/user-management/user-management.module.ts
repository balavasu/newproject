import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LoginComponent } from './login/login.component';
import { UserManagementComponent } from './user-management.component';
import { SignupComponent } from './signup/signup.component';
import { FormsModule } from '@angular/forms';
import { RouterModule, Routes } from '@angular/router';
import { SharedModule } from '../shared/shared.module';
import { ForgotPasswordComponent } from './forgot-password/forgot-password.component';
import { PasswordResetComponent } from './password-reset/password-reset.component';

const routes: Routes = [
  {
    path: '',
      children: 
      [
        {path: 'resetPassword', component:PasswordResetComponent},
        {path: '', component:UserManagementComponent},
      ]
  }
];

@NgModule({
  declarations: [LoginComponent, UserManagementComponent, SignupComponent, ForgotPasswordComponent, PasswordResetComponent],
  imports: [
    CommonModule,
    FormsModule,
    SharedModule,
    RouterModule.forChild([ {path: '', component:UserManagementComponent}])
  ]
})
export class UserManagementModule { 
}
