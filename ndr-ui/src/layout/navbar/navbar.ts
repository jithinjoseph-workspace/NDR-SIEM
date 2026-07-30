import { Component, OnInit, OnDestroy, ChangeDetectorRef, ElementRef, HostListener, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth/auth';
import { LucideAngularModule, Search, Bell, User, ChevronDown, HelpCircle, Settings, LogOut } from 'lucide-angular';
import { Websocket } from '../../services/websocket/websocket';
import { Notifications, ThreatNotification } from '../../services/notifications/notifications';
import { Announcement, Api } from '../../services/api/api';
import { TourService } from '../../services/tour/tour.service';
import { SensorScopeBanner } from '../../components/sensor-scope-banner/sensor-scope-banner';

@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, FormsModule, SensorScopeBanner],
  templateUrl: './navbar.html',
  styleUrl: './navbar.css',
})
export class Navbar implements OnInit, OnDestroy {
  SearchIcon = Search;
  BellIcon = Bell;
  UserIcon = User;
  ChevronDownIcon = ChevronDown;
  HelpCircleIcon = HelpCircle;
  SettingsIcon = Settings;
  LogOutIcon = LogOut;

  systemStatus = 'OPERATIONAL';
  searchText = '';
  showSuggestions = false;
  showUserMenu = false;
  showNotifications = false;
  alertCount = 0;
  recentAlerts: ThreatNotification[] = [];
  activeAnnouncements: Announcement[] = [];
  expandedAnnouncements = new Set<string>();

  toggleAnnouncementExpand(id: string) {
    if (this.expandedAnnouncements.has(id)) {
      this.expandedAnnouncements.delete(id);
    } else {
      this.expandedAnnouncements.add(id);
    }
  }

  isAnnouncementExpanded(id: string): boolean {
    return this.expandedAnnouncements.has(id);
  }

  suggestions = [
    { label: 'Network Logs', hint: 'View all events', route: '/logs', permission: 'logs' },
    { label: 'Alerts', hint: 'View correlation hits', route: '/alerts', permission: 'alerts' },
    { label: 'Rules', hint: 'Manage SIGMA rules', route: '/rules', permission: 'rules' },
    { label: 'Threat Intel', hint: 'IOC lookup', route: '/intel', permission: 'intel' },
    { label: 'Attack Map', hint: 'Global threat map', route: '/analyst/threat-map', permission: 'intel' },
    { label: 'Network Map', hint: 'Topology view', route: '/network-map', permission: 'network-map' },
    { label: 'System Health', hint: 'Service status', route: '/health', permission: 'health' },
    { label: 'Live Stream', hint: 'Real-time events', route: '/live', permission: 'live' },
  ];

  filteredSuggestions: any[] = [];
  private tour = inject(TourService);
  private statusInterval: ReturnType<typeof setInterval> | null = null;
  private announcementInterval: ReturnType<typeof setInterval> | null = null;

  get permittedSuggestions() {
    return this.suggestions.filter(s => this.canAccessRoute(s.route, s.permission));
  }

  get canViewAlerts() {
    return this.canOpenPermission('alerts');
  }

  get notificationCount() {
    return this.alertCount + this.unreadAnnouncementCount;
  }

  get unreadAnnouncementCount() {
    return this.activeAnnouncements.filter(announcement => !announcement.read).length;
  }

  get canShowNotifications() {
    return this.canViewAlerts || this.activeAnnouncements.length > 0;
  }

  get hasNotificationItems() {
    return this.activeAnnouncements.length > 0 || (this.canViewAlerts && this.recentAlerts.length > 0);
  }

  get canViewSettings() {
    return !this.auth.isAdmin();
  }

  get canViewTutorial() {
    const user = this.auth.getUser();
    if (!user) return false;
    return !this.auth.isAdmin() && user.role !== 'tenant_admin';
  }

  constructor(
    private auth: AuthService,
    private router: Router,
    private ws: Websocket,
    private notifications: Notifications,
    private api: Api,
    private cdr: ChangeDetectorRef,
    private el: ElementRef,
  ) {}

  startTutorial() {
    this.tour.startTour();
  }

  @HostListener('document:click', ['$event'])
  onDocumentClick(event: MouseEvent) {
    const target = event.target as HTMLElement;
    
    if (this.showNotifications) {
      const wrap = this.el.nativeElement.querySelector('.notification-wrap');
      if (wrap && !wrap.contains(target)) {
        this.showNotifications = false;
        this.cdr.detectChanges();
      }
    }
    
    if (this.showUserMenu) {
      const profileBtn = this.el.nativeElement.querySelector('.profile-button');
      if (profileBtn && !profileBtn.contains(target)) {
        this.showUserMenu = false;
        this.cdr.detectChanges();
      }
    }
  }

  ngOnInit() {
    this.refreshSystemStatus();
    this.statusInterval = setInterval(() => this.refreshSystemStatus(), 10000);
    this.loadActiveAnnouncements();
    this.announcementInterval = setInterval(() => this.loadActiveAnnouncements(), 60000);

    this.ws.lastAgentStatus$.subscribe(data => {
      if (!data) return;
      this.applySystemStatus(data);
      this.cdr.detectChanges();
    });

    this.notifications.unreadCount$.subscribe(count => {
      this.alertCount = count;
      this.cdr.detectChanges();
    });

    this.notifications.alerts$.subscribe(alerts => {
      this.recentAlerts = alerts.slice(0, 5);
      this.cdr.detectChanges();
    });
  }

  onSearchInput() {
    const term = this.searchText.toLowerCase().trim();
    if (!term) {
      this.showSuggestions = false;
      return;
    }

    this.filteredSuggestions = this.suggestions.filter(s =>
      this.canAccessRoute(s.route, s.permission) &&
      (s.label.toLowerCase().includes(term) || s.hint.toLowerCase().includes(term))
    );

    const ipPattern = /^[\d\.:a-f]+$/i;
    if (ipPattern.test(term) && this.canAccessRoute('/logs', 'logs')) {
      this.filteredSuggestions.unshift({
        label: `Search IP: ${this.searchText}`,
        hint: 'Search in Network Logs',
        route: `/logs?search=${this.searchText}`,
        permission: 'logs',
      });
    }

    if (term.length > 2 && this.canAccessRoute('/rules', 'rules')) {
      this.filteredSuggestions.push({
        label: `Search rules: "${this.searchText}"`,
        hint: 'Find SIGMA rules',
        route: `/rules?search=${this.searchText}`,
        permission: 'rules',
      });
    }

    this.showSuggestions = this.filteredSuggestions.length > 0;
    this.cdr.detectChanges();
  }

  onSearch(event: KeyboardEvent) {
    if (event.key === 'Enter') {
      this.executeSearch();
    }
    if (event.key === 'Escape') {
      this.showSuggestions = false;
    }
  }

  executeSearch() {
    const term = this.searchText.toLowerCase().trim();
    if (!term) return;

    if (term.match(/^\d+\.\d+\.\d+\.\d+/) || term.includes(':')) {
      this.navigateIfAllowed('/logs', 'logs', { search: this.searchText });
    } else if (term.includes('alert') || term.includes('hit')) {
      this.navigateIfAllowed('/alerts', 'alerts');
    } else if (term.includes('rule') || term.includes('sigma')) {
      this.navigateIfAllowed('/rules', 'rules');
    } else if (term.includes('threat') || term.includes('intel') || term.includes('ioc')) {
      this.navigateIfAllowed('/intel', 'intel');
    } else if (term.includes('health') || term.includes('status')) {
      this.navigateIfAllowed('/health', 'health');
    } else if (term.includes('live') || term.includes('stream')) {
      this.navigateIfAllowed('/live', 'live');
    } else if (term.includes('map') || term.includes('topology')) {
      this.navigateIfAllowed('/network-map', 'network-map');
    } else {
      this.navigateIfAllowed('/logs', 'logs', { search: this.searchText });
    }

    this.showSuggestions = false;
    this.searchText = '';
  }

  selectSuggestion(suggestion: any) {
    if (this.canAccessRoute(suggestion.route, suggestion.permission)) {
      this.router.navigateByUrl(suggestion.route);
    } else {
      this.router.navigate([this.auth.getDefaultRoute()]);
    }
    this.showSuggestions = false;
    this.searchText = '';
  }

  openNotifications() {
    this.showNotifications = !this.showNotifications;
    if (this.showNotifications) {
      this.loadActiveAnnouncements();
      this.notifications.markAllRead();
    }
    this.showSuggestions = false;
    this.cdr.detectChanges();
  }


  viewThreatIntel() {
    this.showNotifications = false;
    this.navigateIfAllowed('/intel', 'intel');
  }

  announcementTypeLabel(type: string | undefined) {
    switch (type) {
      case 'maintenance':
        return 'Maintenance';
      case 'update':
        return 'Platform Update';
      case 'critical':
        return 'Critical';
      default:
        return 'Information';
    }
  }

  announcementTypeClass(type: string | undefined) {
    return `announcement-${type || 'info'}`;
  }

  closeSearch() {
    setTimeout(() => {
      this.showSuggestions = false;
      this.cdr.detectChanges();
    }, 200);
  }

  get currentUser() {
    return this.auth.getUser();
  }

  get showSensorScope(): boolean {
    const role = this.currentUser?.role;
    return role === 'analyst' || role === 'senior_analyst' || role === 'viewer';
  }

  get sensorIds(): string[] {
    return this.auth.getSensorIds() || [];
  }

  goToSettings() {
    this.showUserMenu = false;
    if (this.auth.isTenantAdmin()) {
      this.router.navigate(['/tenant-admin/settings']);
    } else {
      this.router.navigate(['/settings']);
    }
  }

  goToSupport() {
    this.showUserMenu = false;
    if (this.auth.isTenantAdmin()) {
      this.router.navigate(['/tenant-admin/support']);
    } else {
      this.router.navigate(['/support']);
    }
  }

  logout() {
    this.showUserMenu = false;
    this.auth.logout();
  }

  ngOnDestroy() {
    if (this.statusInterval) clearInterval(this.statusInterval);
    if (this.announcementInterval) clearInterval(this.announcementInterval);
  }

  private canOpenPermission(permission: string) {
    return this.auth.hasPermission(permission);
  }

  private canAccessRoute(route: string, permission: string): boolean {
    const user = this.auth.getUser();
    if (!user) return false;

    const analystRoutes = ['/logs', '/alerts', '/rules', '/intel', '/network-map', '/health', '/live', '/threat-map', '/analyst/threat-map'];
    if (analystRoutes.includes(route) || route.startsWith('/logs?') || route.startsWith('/rules?')) {
      if (this.auth.isAdmin() || user.role === 'tenant_admin') {
        return false;
      }
    }

    return this.auth.hasPermission(permission);
  }

  private refreshSystemStatus() {
    const user = this.auth.getUser();
    if (user?.tenant_id && user.tenant_id !== 'default') {
      this.refreshTenantSystemStatus();
      return;
    }

    this.api.getAgentStatus().subscribe({
      next: data => {
        this.applySystemStatus(data);
        this.cdr.detectChanges();
      },
    });
  }

  private loadActiveAnnouncements() {
    this.api.getActiveAnnouncements().subscribe({
      next: announcements => {
        this.activeAnnouncements = announcements;
        if (this.showNotifications) {
          this.markUnreadAnnouncementsRead();
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.activeAnnouncements = [];
        this.cdr.detectChanges();
      },
    });
  }

  private markUnreadAnnouncementsRead() {
    const unread = this.activeAnnouncements.filter(announcement => !announcement.read);
    if (unread.length === 0) return;

    unread.forEach(announcement => {
      announcement.read = true;
      this.api.markAnnouncementRead(announcement.id).subscribe({
        error: () => {
          announcement.read = false;
          this.cdr.detectChanges();
        },
      });
    });
    this.cdr.detectChanges();
  }

  private refreshTenantSystemStatus() {
    this.api.getSensorKeys().subscribe({
      next: sensors => {
        const user = this.auth.getUser();
        const mySensorIds = user?.sensor_ids || [];

        // Backend already scopes sensors to the tenant.
        // If user is a restricted analyst, filter down to their assigned sensors.
        const isRestrictedAnalyst = user?.role !== 'tenant_admin' && user?.role !== 'admin' && mySensorIds.length > 0;
        
        const mySensors = isRestrictedAnalyst 
          ? sensors.filter(sensor => mySensorIds.includes(sensor.key_prefix))
          : sensors;

        let healthyPipeline = false;
        
        if (mySensors.length === 0) {
          // If the tenant has absolutely zero sensors registered, assume operational (don't show degraded for a blank account)
          healthyPipeline = true;
        } else {
          // Pipeline is healthy if AT LEAST ONE sensor is active and has valid agents (ignoring strict heartbeat for demo environments)
          healthyPipeline = mySensors.some(sensor =>
            sensor.active !== false &&
            (this.isRunning(sensor['agent-z']) ||
             this.isRunning(sensor['agent-s']) ||
             this.isRunning(sensor.vector))
          );
        }

        this.api.getDashboardStats().subscribe({
          next: data => {
            const services = data?.services || {};
            const platformHealthy =
              this.isRunning(services.kafka) &&
              this.isRunning(services.clickhouse) &&
              this.isRunning(services.engine || 'running');

            this.systemStatus = healthyPipeline && platformHealthy ? 'OPERATIONAL' : 'DEGRADED';
            this.cdr.detectChanges();
          },
          error: () => {
            this.systemStatus = 'DEGRADED';
            this.cdr.detectChanges();
          },
        });
      },
      error: () => {
        this.systemStatus = 'DEGRADED';
        this.cdr.detectChanges();
      },
    });
  }

  private applySystemStatus(data: any) {
    const zeekRunning = this.isRunning(data?.['agent-z']);
    const suricataRunning = this.isRunning(data?.['agent-s']);
    const vectorRunning = this.isRunning(data?.vector);
    this.systemStatus = zeekRunning || suricataRunning || vectorRunning ? 'OPERATIONAL' : 'DEGRADED';
  }

  private isRunning(status: unknown) {
    const value = String(status || '').toLowerCase().trim();
    // 'unknown' is allowed because external sensors may not report process state; we rely on heartbeats.
    if (['running', 'healthy', 'ok', 'up', 'active', 'started', 'unknown'].includes(value)) return true;
    return /^\d+$/.test(value);
  }

  private isRecentlySeen(value: string | undefined) {
    if (!value) return false;
    const normalized = value.includes('T') ? value : value.replace(' ', 'T');
    const withTimezone = /Z$|[+-]\d{2}:\d{2}$/.test(normalized)
      ? normalized
      : `${normalized}Z`;
    const timestamp = new Date(withTimezone).getTime();
    return !Number.isNaN(timestamp) && Date.now() - timestamp <= 2 * 60 * 1000;
  }

  private navigateIfAllowed(route: string, permission: string, queryParams?: Record<string, string>) {
    if (!this.canAccessRoute(route, permission)) {
      this.router.navigate([this.auth.getDefaultRoute()]);
      return;
    }

    this.router.navigate([route], queryParams ? { queryParams } : undefined);
  }
}
