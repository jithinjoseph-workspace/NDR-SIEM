import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LucideAngularModule, Search, Bell, User, ChevronDown } from 'lucide-angular';

@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './navbar.html',
  styleUrl: './navbar.css',
})
export class Navbar {
  SearchIcon = Search;
  BellIcon = Bell;
  UserIcon = User;
  ChevronDownIcon = ChevronDown;
  
  systemStatus = 'OPERATIONAL';
  lastScan = '2m ago';
}

