import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

const routes: Routes = [
  { path: 'admin/dashboard', loadChildren: './admin/admin.module#AdminModule' },
  { path: 'user/dashboard', loadChildren: './user/user.module#UserModule' },
  { path: '**', loadChildren: './user-management/user-management.module#UserManagementModule' },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
