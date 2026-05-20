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
  Zap,
  Users,
  LucideAngularModule
} from 'lucide-angular';
import { AuthService } from '../../services/auth/auth';

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [CommonModule, RouterModule, LucideAngularModule],
  templateUrl: './sidebar.html',
  styleUrl: './sidebar.css',
})
export class Sidebar implements OnInit {
  orgName = 'NDR';
  systemName = 'Network Detection & Response';
  navItems: any[] = [];
  bottomItems: any[] = [];

  constructor(private auth: AuthService) {}

  ngOnInit() {
    if (this.auth.isAdmin()) {
      this.navItems = [
        { label: 'Admin Panel', route: '/admin', icon: Users },
        // You can add other admin-specific menus here
      ];
    } else {
      this.navItems = [
        { label: 'Dashboard', route: '/dashboard', icon: LayoutDashboard },
        { label: 'Alerts', route: '/alerts', icon: Bell },
        { label: 'Network Logs', route: '/logs', icon: FileText },
        { label: 'Live Stream', route: '/live', icon: Activity },
        { label: 'Network Map', route: '/network-map', icon: Network },
        { label: 'Rules', route: '/rules', icon: ShieldAlert },
        { label: 'Threat Intel', route: '/intel', icon: Search },
        { label: 'System Health', route: '/health', icon: Database },
        { label: 'Sensor Setup', route: '/setup', icon: Settings },
        { label: 'SOAR',    route: '/soar',    icon: Zap }
      ];
    }

    this.bottomItems = [
      { label: 'Settings', route: '/settings', icon: Settings },
      { label: 'Support', route: '/support', icon: HelpCircle },
    ];
  }
}
