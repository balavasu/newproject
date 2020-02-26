import { Component, OnInit, ViewChild, TemplateRef } from '@angular/core';
import { Cookie } from 'ng2-cookies';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { Router } from '@angular/router';
import { AppService } from '../services/app.service';
import { ToastrService } from 'ngx-toastr';
import { SocketService } from '../services/socket.service';
import { CalendarEvent } from 'angular-calendar';
import { BsModalService, BsModalRef } from 'ngx-bootstrap/modal';

@Component({
  selector: 'app-user-dashboard',
  templateUrl: './user-dashboard.component.html',
  styleUrls: ['./user-dashboard.component.scss']
})
export class UserDashboardComponent implements OnInit {

  public title: string;
  public inviter: any;
  public invitee: any;
  public start: any;
  public end: any;
  public authToken: any
  public allUsers: any[];
  public meetings: any = []
  public allUsersData: any[]
  public isAdmin: any
  public userSortedList: any;
  public events: CalendarEvent[] = [];
  public selectedMeetingForView: any;
  public isLoading: boolean = true;
  public showMeetingDetails: boolean = false;
  public meetingModalRef: BsModalRef;
  public remiderModalRef: BsModalRef;

  @ViewChild('meetingTemplate', { static: true }) meetingTemplate: TemplateRef<any>;
  @ViewChild('reminderTemplate', { static: true }) reminderTemplate: TemplateRef<any>;
  public isReminderSnooze: boolean = true;
  meetingEvent: any;

  ngOnInit() {
    this.authToken = Cookie.get('authToken');
    this.isAdmin = Cookie.get('activeUserType') === 'admin';

    if (Cookie.get('authToken') == null || Cookie.get('authToken') == '' || Cookie.get('authToken') == undefined) {
      if (this.meetingModalRef) {
        this.meetingModalRef.hide();
      }
      if (this.remiderModalRef) {
        this.remiderModalRef.hide();
      }
      this.router.navigate(['']);
    }
    if (this.isAdmin === false) {
      this.getMeetings();
    } else {
      this.router.navigate(['']);
    }

    // remider every 5 second
    setInterval(() => {
       this.meetingReminder()
    }, 5000)
  }

  modalData: {
    action: string;
    event: CalendarEvent;
  };

  constructor(
    private router: Router,
    public appService: AppService,
    public toastr: ToastrService,
    public socketService: SocketService,
    private modalService: BsModalService) {
  }

  public getMeetings(): void {
    // function call on page-load to get meetings to display in calender view.
    this.appService.getMeetingsByInvitee()
      .subscribe((response) => {
        this.isLoading = false;
        if (response.status == 200) {
          this.meetings = response.data;
          for (let event of this.meetings) {
            event.title = event.title;
            event.start = this.getDateObject(event.start);
            event.end = this.getDateObject(event.end);
            event.color = event.color;
            event.actions = null;
            event.remindMe = true;
          }
          this.events = this.meetings
          this.toastr.success('meetings found for you');
        } else {
          this.toastr.error(response.message);
          this.meetings = [];
        }
      }, (error) => {
        this.isLoading = false;
        this.toastr.error('something went wrong' + error);
        this.meetings = [];
      })
  }

  public onCalendarEvent(calendarEvent): void {
    // function called when user click to view meeting details
    if (calendarEvent.action == 'view') {
      this.isLoading = true;
      this.showMeetingDetails = true;
      this.selectedMeetingForView = calendarEvent.event;
      this.appService.getUserById(calendarEvent.event.inviter)
        .subscribe((response) => {
          this.isLoading = false;
          if (response.status == 200) {
            this.selectedMeetingForView['inviterFullName'] = `${response.data.firstName} ${response.data.lastName} (${response.data.userName})`
            this.meetingModalRef = this.modalService.show(this.meetingTemplate);
          } else {
            this.toastr.error(response.message);
          }
        }, (error) => {
          this.isLoading = false;
          this.toastr.error('something went wrong' + error);
        })
    }
  }

  public closeModal(): void {
    // function to close the meeting modal
    this.getMeetings();
    this.meetingModalRef.hide();
  }

  public meetingReminder(): void {
    // function called for meeting reminder
    let currentTime = new Date().getTime();
    for (let meeting of this.meetings) {
      let timeDifference = (meeting.start).getTime() - currentTime;
      if (timeDifference <= 60000 && timeDifference > 0) {
        if ((this.isReminderSnooze || this.meetingEvent != meeting) && Cookie.get('authToken') != null) {
          this.isReminderSnooze = false;
          this.meetingEvent = meeting;
          this.remiderModalRef = this.modalService.show(this.reminderTemplate);
          break;
        }
      } else if ((meeting.start).getTime() == currentTime && Cookie.get('authToken') != null) {
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

  private getDateObject(date): Date {
    return new Date(
      new Date(date).getUTCFullYear(),
      new Date(date).getUTCMonth(),
      new Date(date).getUTCDate(),
      new Date(date).getUTCHours(),
      new Date(date).getUTCMinutes());
  }

}
