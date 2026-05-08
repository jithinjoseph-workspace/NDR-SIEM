import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { 
  LayoutDashboard, 
  Bell, 
  FileText, 
  Activity, 
  ShieldAlert, 
  Search, 
  Database, 
  Settings,
  HelpCircle,
  Network,
  LucideAngularModule
} from 'lucide-angular';

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [CommonModule, RouterModule, LucideAngularModule],
  templateUrl: './sidebar.html',
  styleUrl: './sidebar.css',
})
export class Sidebar implements OnInit {
  orgName = 'NDR Command';
  systemName = 'Tactical Observatory';

  navItems = [
    { label: 'Dashboard', route: '/dashboard', icon: LayoutDashboard },
    { label: 'Alerts', route: '/alerts', icon: Bell },
    { label: 'Network Logs', route: '/logs', icon: FileText },
    { label: 'Live Stream', route: '/live', icon: Activity },
    { label: 'Network Map', route: '/network-map', icon: Network },
    { label: 'Rules', route: '/rules', icon: ShieldAlert },
    { label: 'Threat Intel', route: '/intel', icon: Search },
    { label: 'System Health', route: '/health', icon: Database },
    { label: 'Sensor Setup', route: '/setup', icon: Settings },
  ];

  bottomItems = [
    { label: 'Settings', route: '/settings', icon: Settings },
    { label: 'Support', route: '/support', icon: HelpCircle },
  ];

  constructor(private http: HttpClient) {}

  ngOnInit() {
    this.http.get<any>('http://localhost:3000/api/settings').subscribe({
      next: (s) => {
        if (s?.org_name) this.orgName = s.org_name;
        if (s?.system_name) this.systemName = s.system_name;
      }
    });
  }
}

