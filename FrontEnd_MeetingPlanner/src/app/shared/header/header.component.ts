import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { Cookie } from 'ng2-cookies';
import { AppService } from 'src/app/services/app.service';
import { ToastrService } from 'ngx-toastr';

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.scss']
})
export class HeaderComponent implements OnInit {

  public authToken: string;
  public activeUser: string;

  constructor(
    private router: Router,
    private appService: AppService,
    private toastr: ToastrService,
    private activatedRoute: ActivatedRoute
  ) { }

  ngOnInit() {
    if (this.activatedRoute.snapshot.component['name'] == "UserManagementComponent") {
      this.authToken = null;
      this.activeUser = null;
    } else {
      this.authToken = Cookie.get('authToken');
      if(!this.authToken){
        this.router.navigate(['']);
      }else{
        this.activeUser = Cookie.get('activeUserFullName');
      }
    }
    // call logout function on click of browser back url
    window.onpopstate = ()=> {
      this.logout();
    }
  }

  // call logout function on click of logout 
  public logout(): void {
    this.appService.logout()
      .subscribe((apiResponse) => {
        if (apiResponse.status === 200) {
          Cookie.deleteAll();
          this.authToken = null;
          this.activeUser = null;
          this.router.navigate(['']);
        } else {
          Cookie.deleteAll();
          this.toastr.error(apiResponse.message);
        }
      }, (err) => {
        Cookie.deleteAll();
        this.toastr.error('some error occured');
      });
  }
 

}







