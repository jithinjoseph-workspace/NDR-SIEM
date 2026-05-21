import { Component, OnInit, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterOutlet, NavigationEnd } from '@angular/router';
import { Sidebar } from '../layout/sidebar/sidebar';
import { Navbar } from '../layout/navbar/navbar';
import { Websocket } from '../services/websocket/websocket';
import { AuthService } from '../services/auth/auth';
import { filter } from 'rxjs/operators';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, Sidebar, Navbar],
  templateUrl: './app.html',
  styleUrl: './app.css',
  encapsulation: ViewEncapsulation.None
})
export class App implements OnInit {
  showShell = false;

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
      });

    // Initial check (before first NavigationEnd fires)
    const url = this.router.url;
    const isLoginPage = url === '/login' || url.startsWith('/login?');
    this.showShell = !isLoginPage && this.auth.isLoggedIn();

    // Connect WebSocket only when authenticated
    if (this.auth.isLoggedIn()) {
      this.wsService.connect();
    }
  }
}
