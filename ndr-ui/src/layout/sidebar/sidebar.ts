import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
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
  LucideAngularModule
} from 'lucide-angular';

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [CommonModule, RouterModule, LucideAngularModule],
  templateUrl: './sidebar.html',
  styleUrl: './sidebar.css',
})
export class Sidebar {
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
    { label: 'SOAR',    route: '/soar',    icon: Zap }
  ];

  bottomItems = [
    { label: 'Settings', route: '/settings', icon: Settings },
    { label: 'Support', route: '/support', icon: HelpCircle },
  ];
}

