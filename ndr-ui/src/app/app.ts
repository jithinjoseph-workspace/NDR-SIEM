import { Component, OnInit, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
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
  constructor(private wsService: Websocket) { }

  ngOnInit() {
    // Connect inside Angular lifecycle — zone is fully ready here
    this.wsService.connect();
  }
}
