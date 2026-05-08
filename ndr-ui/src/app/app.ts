import { Component, OnInit, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { Sidebar } from '../layout/sidebar/sidebar';
import { Navbar } from '../layout/navbar/navbar';
import { Websocket } from '../services/websocket/websocket';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, Sidebar, Navbar],
  templateUrl: './app.html',
  styleUrl: './app.css',
  encapsulation: ViewEncapsulation.None
})
export class App implements OnInit {
  constructor(
    private wsService: Websocket,
    private http: HttpClient
  ) { }

  ngOnInit() {
    // Load theme from backend settings
    this.http.get<any>('http://localhost:3000/api/settings').subscribe({
      next: (s) => {
        const theme = s?.theme || 'dark';
        document.documentElement.setAttribute('data-theme', theme);
      },
      error: () => {
        // Default to dark on error
        document.documentElement.setAttribute('data-theme', 'dark');
      }
    });

    // Connect inside Angular lifecycle — zone is fully ready here
    this.wsService.connect();
  }
}
