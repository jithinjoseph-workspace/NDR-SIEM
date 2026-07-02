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
  Building2,
  Gauge,
  KeyRound,
  Megaphone,
  ShieldCheck,
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

    if (this.auth.isAdmin()) {
      this.navItems = [
        { label: 'Tenants',       route: '/admin', queryParams: { tab: 'tenants' },       icon: Building2 },
        { label: 'Users',         route: '/admin', queryParams: { tab: 'users' },          icon: Users },
        { label: 'Engines',       route: '/admin', queryParams: { tab: 'engines' },        icon: Gauge },
        { label: 'Sensors',       route: '/admin', queryParams: { tab: 'sensors' },        icon: KeyRound },
        { label: 'Announcements', route: '/admin', queryParams: { tab: 'announcements' },   icon: Megaphone },
        { label: 'Telemetry',     route: '/admin', queryParams: { tab: 'telemetry' },       icon: Activity },
        { label: 'Trusted Cloud', route: '/admin', queryParams: { tab: 'trusted-cloud' },   icon: ShieldCheck },
        { label: 'AI Providers',  route: '/admin', queryParams: { tab: 'ai-providers' },    icon: Bot },
      ];
    } else if (user?.role === 'tenant_admin') {
      this.navItems = [
        { label: 'Tenant Users', route: '/tenant-admin', icon: Users },
        { label: 'Sensor Setup', route: '/setup',        icon: Settings },
      ];
    } else {
      this.navItems = [
        { label: 'Dashboard',    route: '/dashboard',    icon: LayoutDashboard, permission: 'dashboard' },
        { label: 'Alerts',       route: '/alerts',       icon: Bell,            permission: 'alerts' },
        { label: 'Network Logs', route: '/logs',         icon: FileText,        permission: 'logs' },
        { label: 'Live Stream',  route: '/live',         icon: Activity,        permission: 'live' },
        { label: 'Network Map',  route: '/network-map',  icon: Network,         permission: 'network-map' },
        { label: 'Assets',       route: '/assets',       icon: Server,          permission: 'assets' },
        { label: 'Rules',        route: '/rules',        icon: ShieldAlert,     permission: 'rules' },
        { label: 'Threat Intel', route: '/intel',        icon: Search,          permission: 'intel' },
        { label: 'System Health',route: '/health',       icon: Database,        permission: 'health' },
      ].filter(item => this.auth.hasPermission(item.permission));

      if (isDefaultTenant && this.auth.hasPermission('setup')) {
        this.navItems.push({ label: 'Sensor Setup', route: '/setup', icon: Settings, permission: 'setup' });
      }

      if (this.auth.hasPermission('soar')) {
        this.navItems.push({ label: 'SOAR', route: '/soar', icon: Zap, permission: 'soar' });
      }

      if (this.auth.hasPermission('evidence')) {
        this.navItems.push({ label: 'Evidence',    route: '/evidence',    icon: FolderSearch, permission: 'evidence' });
      }
      if (this.auth.hasPermission('ai-activity')) {
        this.navItems.push({ label: 'AI Activity', route: '/ai-activity', icon: Bot,          permission: 'ai-activity' });
      }
    }

    this.bottomItems = [];
    if (!this.auth.isAdmin()) {
      this.bottomItems.push({ label: 'Settings', route: '/settings', icon: Settings });
    }
    this.bottomItems.push({ label: 'Support', route: '/support', icon: HelpCircle });
  }

  isActive(item: any): boolean {
    if (item.queryParams) {
      const urlTree = this.router.createUrlTree([item.route], { queryParams: item.queryParams });
      return this.router.isActive(urlTree, { paths: 'exact', queryParams: 'exact', fragment: 'ignored', matrixParams: 'ignored' });
    } else {
      return this.router.isActive(item.route, { paths: 'exact', queryParams: 'ignored', fragment: 'ignored', matrixParams: 'ignored' });
    }
  }
}
