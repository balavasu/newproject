import { Component, ViewChild, TemplateRef, OnInit } from '@angular/core';
import { CalendarEvent } from 'angular-calendar';
import { Router } from '@angular/router';
import { AppService } from '../services/app.service';
import { ToastrService } from 'ngx-toastr';
import { SocketService } from '../services/socket.service';
import { Cookie } from 'ng2-cookies';
import { BsModalService, BsModalRef } from 'ngx-bootstrap/modal';

@Component({
  selector: 'app-admin-dashboard',
  templateUrl: './admin-dashboard.component.html',
  styleUrls: ['./admin-dashboard.component.scss']
})
export class AdminDashboardComponent implements OnInit {

  @ViewChild('meetingTemplate', { static: true }) meetingTemplate: TemplateRef<any>;
  @ViewChild('reminderTemplate', { static: true }) reminderTemplate: TemplateRef<any>;

  public meetingModalRef: BsModalRef;
  public remiderModalRef: BsModalRef;
  public inviter: any;
  public authToken: any
  public meetings: any = [];
  public meetingListForReminder: any[];
  public userList: any[];
  public userSortedList: any[];
  public showUserList: boolean = true;
  public showCalender: boolean = false;
  public isEditMeeting: boolean = false;
  public selectedMeeting: any;
  public selectedDate: any;
  public selectedUser: any;
  public calendarAction: string;
  public events: CalendarEvent[] = [];
  public isReminderSnooze: boolean = true;
  public meetingEvent: any;
  public isAdmin :boolean; 
  public isLoading: boolean = true;

  constructor(
    private router: Router,
    public appService: AppService,
    public toastr: ToastrService,
    public socketService: SocketService,
    private modalService: BsModalService) { }

  ngOnInit() {
    this.inviter = Cookie.get('activeUserId')
    this.authToken = Cookie.get('authToken');
    this.isAdmin = Cookie.get('activeUserType') === 'admin';
    // check authToken, if not found then redirect to login page
    if (Cookie.get('authToken') == null || Cookie.get('authToken') == '' || Cookie.get('authToken') == undefined) {
      if (this.meetingModalRef) {
        this.meetingModalRef.hide();
      }
      if (this.remiderModalRef) {
        this.remiderModalRef.hide();
      }
      this.isLoading = false;
      this.router.navigate(['']);
    }
    if (this.isAdmin) {
      this.getAllUsers();
      this.getMeetingsByInviter();
    } else {
      this.isLoading = false;
      this.router.navigate(['']);
    }
    // meeting remider for every 5 second
    setInterval(() => {
      if(this.meetingListForReminder){
        this.meetingReminder();
      }
    }, 5000)
  }

  private getAllUsers(): void {
    // private function to get list of all users and display on admin dashboard
    if (this.authToken) {
      this.appService.getUsers()
        .subscribe((response) => {
          this.isLoading = false;
          if (response.status === 200) {
            let responseData = response.data;
            this.userList = []
            for (let i = 0; i < responseData.length; i++) {
              let user = {
                fullName: `${responseData[i].firstName} ${responseData[i].lastName}`,
                userName: responseData[i].userName,
                email: responseData[i].email,
                mobile: `+${responseData[i].countryCode} ${responseData[i].mobileNumber}`,
                userId: responseData[i].userId,
                isAdmin: responseData[i].isAdmin
              }
              this.userList.push(user)
              this.userSortedList = this.userList.sort((user1, user2) => {
                if (user1.fullName > user2.fullName) { return 1; }
                if (user1.fullName < user2.fullName) { return -1; }
                return 0;
              });
            }
          } else {
            this.toastr.error(response.message);
          }
        }, (error) => {
          this.isLoading = false;
          this.toastr.error('something went wrong');
        })
    } else {
      this.toastr.info('Something went wrong, please login again.');
      if (this.meetingModalRef) {
        this.meetingModalRef.hide();
      }
      if (this.remiderModalRef) {
        this.remiderModalRef.hide();
      }
      this.router.navigate(['']);
    }
  }

  private getMeetingsByInviter(): void{
    // get all meetings scheduled by active admin for reminder
    this.appService.getMeetingsByInviter()
        .subscribe((response) => {
          if (response.status === 200) {
            this.meetingListForReminder = response.data;
          } else {
            this.toastr.error(response.message);
          }
        }, (error) => {
          this.toastr.error('something went wrong');
        })
  }

  public displaySelectedUserMeetings(selectedUser, isFirstCall) {
    // function to get meeting of selected user by admin 
    this.isLoading = true;
    this.selectedUser = selectedUser;
    Cookie.delete('selectedUserId');
    Cookie.delete('selectedUserFullName');
    Cookie.delete('selectedUserEmail');
    Cookie.set('selectedUserId', selectedUser.userId);
    Cookie.set('selectedUserFullName', `${selectedUser.fullName} (${selectedUser.userName})`);
    Cookie.set('selectedUserEmail', selectedUser.email);
    this.appService.getSelectedUserMeetings(this.inviter, selectedUser.userId, this.authToken)
      .subscribe((data) => {
        this.isLoading = false;
        if (data.status === 200) {
          this.meetings = data.data
          for (let event of this.meetings) {
            event.title = event.title;
            event.start = this.getDateObject(event.start);
            event.end = this.getDateObject(event.end);
            event.color = event.color;
            event.actions = null;
            event.remindMe = true;
          }
          this.events = this.meetings
          if (isFirstCall) {
            this.toastr.success('meetings found for selected user');
          }
          this.showCalender = true;
          this.showUserList = false;
        } else {
          this.toastr.error(data.message)
          this.showCalender = true;
          this.showUserList = false;
          this.meetings = []
        }
      }, (error) => {
        this.isLoading = false;
        this.toastr.error('something went wrong' + error);
        this.showCalender = false;
        this.showUserList = true;
        this.meetings = []
      })
  }

  public onCalendarEvent(calendarEvent): any {
    this.calendarAction = calendarEvent.action;
    if (calendarEvent.action == 'create') {
      this.isEditMeeting = false;
      this.selectedDate = { start: calendarEvent.event.selectedDate, end: calendarEvent.event.selectedDate };
    } else if (calendarEvent.action == 'edit') {
      this.isEditMeeting = true;
      this.selectedMeeting = calendarEvent.event;
    } else if (calendarEvent.action == 'delete') {
      this.isLoading = true;
      this.appService.deleteMeeting(calendarEvent.event.meetingId)
        .subscribe((apiResponse) => {
          this.isLoading = false;
          if (apiResponse.status === 200) {
            this.toastr.success('Meeting deleted');
            let meetingNotification = {
              message: `Meeting Canceled. Your meeting with title: "${calendarEvent.event.title}" on ${calendarEvent.event.start} has been cancled.`,
              userId: calendarEvent.event.invitee
            }
            this.socketService.notifyUpdates(meetingNotification);
          } else {
            this.isLoading = false;
            this.toastr.error(apiResponse.message);
          }
        }, (error) => {
          this.isLoading = false;
          this.toastr.error('Error: something went wrong')
        });
    }
    if (calendarEvent.action == 'create' || calendarEvent.action == 'edit') {
      this.meetingModalRef = this.modalService.show(this.meetingTemplate, { class: 'modal-md' });
    }
  }

  private getDateObject(date): Date {
    // private function takes date as argument and returns date in UTC format
    return new Date(
      new Date(date).getUTCFullYear(),
      new Date(date).getUTCMonth(),
      new Date(date).getUTCDate(),
      new Date(date).getUTCHours(),
      new Date(date).getUTCMinutes());
  }

  public onCreateMeetingClicked(): void {
    // function called whrn create new meeting button clicked to disply modal fro meeting
    this.calendarAction = "create";
    this.selectedDate = { start: new Date(), end: new Date() };
    this.meetingModalRef = this.modalService.show(this.meetingTemplate, { class: 'modal-md' });
  }

  public closeMeetingModal(): void {
    // close the meeting form modal on click of close
    this.displaySelectedUserMeetings(this.selectedUser, false);
    this.meetingModalRef.hide();
  }

  public meetingReminder(): void {
    // function called for meeting reminder
    let currentTime = new Date().getTime();
    for (let meeting of this.meetingListForReminder) {
      let meetingTime = (this.getDateObject(meeting.start)).getTime();
      let timeDifference = meetingTime - currentTime;
      if (timeDifference <= 60000 && timeDifference > 0) {
        if ((this.isReminderSnooze || this.meetingEvent != meeting) && Cookie.get('authToken')) {
          this.isReminderSnooze = false;
          this.meetingEvent = meeting;
          this.remiderModalRef = this.modalService.show(this.reminderTemplate);
          break;
        }
      } else if (meetingTime == currentTime &&  Cookie.get('authToken')) {
        this.toastr.info('Meeting started');
      }
    }
  }

  public snoozeRemiderModal(): void {
    // funtion called when meeting reminder snoozed
    this.isReminderSnooze = true;
    this.remiderModalRef.hide();
  }
  public dismissRemiderModal(): void {
     // funtion called when meeting reminder dismissed
    this.remiderModalRef.hide();
  }

  public onClickBack(): void{
    // function called on click of back to user list button, get latest meetings for reminder by calling getMeetingsByInviter
    this.getMeetingsByInviter();
  }
}