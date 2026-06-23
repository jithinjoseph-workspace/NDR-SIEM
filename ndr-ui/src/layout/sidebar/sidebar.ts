import { Component, OnDestroy, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { NavigationEnd, Router, RouterModule } from '@angular/router';
import { filter, Subscription } from 'rxjs';
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
  FolderSearch,
  Bot,
  Server,
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
export class Sidebar implements OnInit, OnDestroy {
  orgName = 'NDR';
  systemName = 'Network Detection & Response';
  navItems: any[] = [];
  bottomItems: any[] = [];
  private navigationSub?: Subscription;

  constructor(
    private auth: AuthService,
    private router: Router
  ) {}

  ngOnInit() {
    this.buildNavigation();
    this.navigationSub = this.router.events
      .pipe(filter(event => event instanceof NavigationEnd))
      .subscribe(() => this.buildNavigation());
  }

  ngOnDestroy() {
    this.navigationSub?.unsubscribe();
  }

  private buildNavigation() {
    const user = this.auth.getUser();
    const isDefaultTenant = user?.tenant_id === 'default';

    if (this.auth.isAdmin() || user?.role === 'tenant_admin') {
      this.navItems = [
        isDefaultTenant
          ? { label: 'Admin Panel', route: '/admin', icon: Users }
          : { label: 'Tenant Users', route: '/tenant-admin', icon: Users },
      ];

      if (user?.role === 'tenant_admin') {
        this.navItems.push({ label: 'Sensor Setup', route: '/setup', icon: Settings });
      }

      this.navItems.push({ label: 'Evidence', route: '/evidence', icon: FolderSearch });
      this.navItems.push({ label: 'AI Activity', route: '/ai-activity', icon: Bot });
    } else {
      this.navItems = [
        { label: 'Dashboard', route: '/dashboard', icon: LayoutDashboard, permission: 'dashboard' },
        { label: 'Alerts', route: '/alerts', icon: Bell, permission: 'alerts' },
        { label: 'Network Logs', route: '/logs', icon: FileText, permission: 'logs' },
        { label: 'Live Stream', route: '/live', icon: Activity, permission: 'live' },
        { label: 'Network Map', route: '/network-map', icon: Network, permission: 'network-map' },
        { label: 'Assets', route: '/assets', icon: Server, permission: 'alerts' },
        { label: 'Rules', route: '/rules', icon: ShieldAlert, permission: 'rules' },
        { label: 'Threat Intel', route: '/intel', icon: Search, permission: 'intel' },
        { label: 'System Health', route: '/health', icon: Database, permission: 'health' },
      ].filter(item => this.auth.hasPermission(item.permission));

      if (isDefaultTenant && this.auth.hasPermission('setup')) {
        this.navItems.push({ label: 'Sensor Setup', route: '/setup', icon: Settings, permission: 'setup' });
      }

      if (this.auth.hasPermission('soar')) {
        this.navItems.push({ label: 'SOAR', route: '/soar', icon: Zap, permission: 'soar' });
      }

      if (this.auth.hasPermission('alerts')) {
        this.navItems.push({ label: 'Evidence', route: '/evidence', icon: FolderSearch, permission: 'alerts' });
        this.navItems.push({ label: 'AI Activity', route: '/ai-activity', icon: Bot, permission: 'alerts' });
      }
    }

    this.bottomItems = [
      { label: 'Settings', route: '/settings', icon: Settings },
      { label: 'Support', route: '/support', icon: HelpCircle },
    ];
  }
}
