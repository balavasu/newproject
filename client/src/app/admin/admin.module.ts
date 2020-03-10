import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AdminDashboardComponent } from './admin-dashboard.component';
import { SharedModule } from '../shared/shared.module';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { OwlDateTimeModule, OwlNativeDateTimeModule } from 'ng-pick-datetime';
import { RouterModule } from '@angular/router';

@NgModule({
  declarations: [AdminDashboardComponent],
  imports: [
    CommonModule,
    SharedModule,
    FormsModule,
    OwlDateTimeModule,
    OwlNativeDateTimeModule,
    ReactiveFormsModule,
    RouterModule.forChild([{ path: '', component: AdminDashboardComponent }])
  ]
})
export class AdminModule { }
