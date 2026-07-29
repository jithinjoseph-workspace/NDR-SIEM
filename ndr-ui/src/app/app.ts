import { Component, OnInit, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterOutlet, NavigationEnd } from '@angular/router';
import { Sidebar } from '../layout/sidebar/sidebar';
import { Navbar } from '../layout/navbar/navbar';
import { Websocket } from '../services/websocket/websocket';
import { AuthService } from '../services/auth/auth';
import { filter } from 'rxjs/operators';
import { ToastContainer } from '../components/toast-container/toast-container';
import { AriaBot } from '../components/aria-bot/aria-bot';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, Sidebar, Navbar, ToastContainer, AriaBot],
  templateUrl: './app.html',
  styleUrl: './app.css',
  encapsulation: ViewEncapsulation.None
})
export class App implements OnInit {
  showShell = false;
  showGlobalSidebar = false;

  constructor(
    private wsService: Websocket,
    private router: Router,
    private auth: AuthService
  ) {}

  ngOnInit() {
    // Determine shell visibility on every navigation
    this.router.events
      .pipe(filter(e => e instanceof NavigationEnd))
      .subscribe((e: any) => {
        const url: string = e.urlAfterRedirects || e.url;
        const isLoginPage = url === '/login' || url.startsWith('/login?');
        this.showShell = !isLoginPage && this.auth.isLoggedIn();
        this.showGlobalSidebar = this.showShell && !url.startsWith('/tenant-admin') && !url.startsWith('/admin');

        // Stop polling when user reaches the login page (covers manual logout
        // or any other redirect that lands on /login)
        if (isLoginPage) {
          this.auth.stopSessionPoll();
        }
      });

    // Initial check (before first NavigationEnd fires)
    const url = this.router.url;
    const isLoginPage = url === '/login' || url.startsWith('/login?');
    this.showShell = !isLoginPage && this.auth.isLoggedIn();
    this.showGlobalSidebar = this.showShell && !url.startsWith('/tenant-admin') && !url.startsWith('/admin');

    // Connect WebSocket only when authenticated
    if (this.auth.isLoggedIn()) {
      this.wsService.connect();

      // Start background session-validity poll so that blocked analyst/viewer
      // accounts are evicted within SESSION_POLL_MS (30 s) even if they never
      // navigate away from their current page.
      this.auth.startSessionPoll();
    }
  }
}
