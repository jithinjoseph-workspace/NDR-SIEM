import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth/auth';
import { LucideAngularModule, Search, Bell, User, ChevronDown } from 'lucide-angular';
import { Websocket } from '../../services/websocket/websocket';
import { Notifications, ThreatNotification } from '../../services/notifications/notifications';

@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, FormsModule],
  templateUrl: './navbar.html',
  styleUrl: './navbar.css',
})
export class Navbar implements OnInit {
  SearchIcon = Search;
  BellIcon = Bell;
  UserIcon = User;
  ChevronDownIcon = ChevronDown;

  systemStatus = 'OPERATIONAL';
  searchText = '';
  showSuggestions = false;
  showUserMenu = false;
  showNotifications = false;
  alertCount = 0;
  recentAlerts: ThreatNotification[] = [];

  suggestions = [
    { label: 'Network Logs', hint: 'View all events', route: '/logs', permission: 'logs' },
    { label: 'Alerts', hint: 'View correlation hits', route: '/alerts', permission: 'alerts' },
    { label: 'Rules', hint: 'Manage SIGMA rules', route: '/rules', permission: 'rules' },
    { label: 'Threat Intel', hint: 'IOC lookup', route: '/intel', permission: 'intel' },
    { label: 'Network Map', hint: 'Topology view', route: '/network-map', permission: 'network-map' },
    { label: 'System Health', hint: 'Service status', route: '/health', permission: 'health' },
    { label: 'Live Stream', hint: 'Real-time events', route: '/live', permission: 'live' },
  ];

  filteredSuggestions: any[] = [];

  get permittedSuggestions() {
    return this.suggestions.filter(s => this.canOpenPermission(s.permission));
  }

  get canViewAlerts() {
    return this.canOpenPermission('alerts');
  }

  constructor(
    private auth: AuthService,
    private router: Router,
    private ws: Websocket,
    private notifications: Notifications,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.ws.lastAgentStatus$.subscribe(data => {
      if (!data) return;
      const allRunning = data.zeek === 'running' && data.suricata === 'running';
      this.systemStatus = allRunning ? 'OPERATIONAL' : 'DEGRADED';
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
      this.canOpenPermission(s.permission) &&
      (s.label.toLowerCase().includes(term) || s.hint.toLowerCase().includes(term))
    );

    const ipPattern = /^[\d\.:a-f]+$/i;
    if (ipPattern.test(term) && this.canOpenPermission('logs')) {
      this.filteredSuggestions.unshift({
        label: `Search IP: ${this.searchText}`,
        hint: 'Search in Network Logs',
        route: `/logs?search=${this.searchText}`,
        permission: 'logs',
      });
    }

    if (term.length > 2 && this.canOpenPermission('rules')) {
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
    if (this.canOpenPermission(suggestion.permission)) {
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
      this.notifications.markAllRead();
    }
    this.showSuggestions = false;
    this.cdr.detectChanges();
  }

  closeNotifications() {
    setTimeout(() => {
      this.showNotifications = false;
      this.cdr.detectChanges();
    }, 150);
  }

  viewThreatIntel() {
    this.showNotifications = false;
    this.navigateIfAllowed('/intel', 'intel');
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

  logout() {
    this.auth.logout();
  }

  private canOpenPermission(permission: string) {
    return this.auth.hasPermission(permission);
  }

  private navigateIfAllowed(route: string, permission: string, queryParams?: Record<string, string>) {
    if (!this.canOpenPermission(permission)) {
      this.router.navigate([this.auth.getDefaultRoute()]);
      return;
    }

    this.router.navigate([route], queryParams ? { queryParams } : undefined);
  }
}
