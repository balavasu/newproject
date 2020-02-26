import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Cookie } from 'ng2-cookies';

@Injectable({
  providedIn: 'root'
})
export class AppService {
  // private url = 'http://rinkesh.cf:3000';
  private url = 'http://localhost:3000';
  signupUrl= `${this.url}/api/v1/users/signup`;
  loginUrl= `${this.url}/api/v1/users/login`;
  logoutUrl= `${this.url}/api/v1/users/logout`;
  forgotPasswordUrl= `${this.url}/api/v1/users/forgotPassword`;
  resetPasswordUrl= `${this.url}/api/v1/users/resetPassword`;
  getUsersUrl= `${this.url}/api/v1/users`;
  getUserByIdUrl= `${this.url}/api/v1/users`;
  
  constructor(public http: HttpClient) {
  }

/*------- USER METHODS START -----------*/
  public signUp(data): Observable<any> {
    const params = new HttpParams()
      .set('userName', data.userName)
      .set('firstName', data.firstName)
      .set('lastName', data.lastName)
      .set('mobileNumber', data.mobileNumber)
      .set('email', data.email)
      .set('password', data.password)
      .set('countryName', data.countryName)
      .set('isAdmin', data.isAdmin)
      .set('countryCode',data.countryCode);
    return this.http.post(this.signupUrl, params);
  }

  public onLogin(data): Observable<any> {
    const params = new HttpParams()
      .set('email', data.email)
      .set('password', data.password)
    return this.http.post(this.loginUrl, params);
  }

  public forgotPassword(data): Observable<any> {
    const params = new HttpParams()
      .set('email', data.email)
    return this.http.post(this.forgotPasswordUrl, params);
  }
  
  public resetPassword(data): Observable<any> {
    const params = new HttpParams()
      .set('userId', data.userId)
      .set('password', data.password)
    return this.http.post(this.resetPasswordUrl, params);
  }
  
  public logout(): Observable<any> {
    const params = new HttpParams()
      .set('authToken', Cookie.get('authToken'))
    return this.http.post(`${this.logoutUrl}/${Cookie.get('activeUserId')}`, params)
  }

  public getUsers(): Observable<any> {
    return this.http.get(`${this.getUsersUrl}?authToken=${Cookie.get('authToken')}`);
  }
  public getUserById(userId): Observable<any> {
    return this.http.get(`${this.getUserByIdUrl}/${userId}?authToken=${Cookie.get('authToken')}`)
  }

/*------- USER METHODS END -----------*/

/*------- MEETING METHODS START -----------*/
  public createMeeting(data): Observable<any> {
    const params = new HttpParams()
      .set('title', data.title)
      .set('inviter', data.inviter)
      .set('invitee', data.invitee)
      .set('purpose',data.purpose)
      .set('start', data.start)
      .set('end', data.end)
      .set('location',data.location)
      .set('inviterEmail',data.inviterEmail)
      .set('inviteeEmail',data.inviteeEmail)
      .set('authToken', Cookie.get('authToken'))
    return this.http.post(`${this.url}/api/v1/meeting/create`, params);
  }

  public getSelectedUserMeetings(inviter, invitee, authToken): Observable<any> {
    return this.http.get(`${this.url}/api/v1/meeting/getByInviterAndInvitee?inviter=${inviter}&invitee=${invitee}&authToken=${Cookie.get('authToken')}`);
  }

  public updateMeeting(data, meetingId): Observable<any> {
    const params = new HttpParams()
      .set('title', data.title)
      .set('start', data.start)
      .set('end', data.end)
      .set('location',data.location)
      .set('purpose',data.purpose)
      .set('inviterEmail',data.inviterEmail)
      .set('inviteeEmail',data.inviteeEmail)
      .set('authToken', Cookie.get('authToken'))
    return this.http.put(`${this.url}/api/v1/meeting/update/${meetingId}`, params);
  }

  public deleteMeeting(meetingId): Observable<any> {
    const params = new HttpParams()
      .set('authToken', Cookie.get('authToken'))
    return this.http.post(`${this.url}/api/v1/meeting/delete/${meetingId}`, params)
  }

  public getMeetingsByInvitee(): Observable<any>{
    return this.http.get(`${this.url}/api/v1/meeting/getByInvitee/${Cookie.get('activeUserId')}?authToken=${Cookie.get('authToken')}`);
  }

  public getMeetingsByInviter(): Observable<any>{
    return this.http.get(`${this.url}/api/v1/meeting/getByInviter/${Cookie.get('activeUserId')}?authToken=${Cookie.get('authToken')}`);
  }

  /*------- MEETING METHODS END -----------*/

  /*------- OTHER METHODS START -----------*/
  public getCountryCodes(): any {
    return this.http.get('assets/countryCodes.json');
  }

  public getCountries(): any {
    return this.http.get('assets/countries.json');
  }
    /*------- OTHER METHODS END -----------*/
}