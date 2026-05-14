import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
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
  SearchIcon     = Search;
  BellIcon       = Bell;
  UserIcon       = User;
  ChevronDownIcon = ChevronDown;

  systemStatus = 'OPERATIONAL';
  searchText   = '';
  showSuggestions = false;
  showNotifications = false;
  alertCount   = 0;
  recentAlerts: ThreatNotification[] = [];

  // Search suggestions
  suggestions = [
    { label: 'Network Logs',   hint: 'View all events',         route: '/logs',        icon: '📋' },
    { label: 'Alerts',         hint: 'View correlation hits',   route: '/alerts',      icon: '🚨' },
    { label: 'Rules',          hint: 'Manage SIGMA rules',      route: '/rules',       icon: '⚙️' },
    { label: 'Threat Intel',   hint: 'IOC lookup',              route: '/intel',       icon: '🛡️' },
    { label: 'Network Map',    hint: 'Topology view',           route: '/network-map', icon: '🗺️' },
    { label: 'System Health',  hint: 'Service status',          route: '/health',      icon: '💚' },
    { label: 'Live Stream',    hint: 'Real-time events',        route: '/live',        icon: '📡' },
  ];

  filteredSuggestions: any[] = [];

  constructor(
    private router: Router,
    private ws: Websocket,
    private notifications: Notifications,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    // Update system status from WebSocket
    this.ws.lastAgentStatus$.subscribe(data => {
      if (!data) return;
      const allRunning = data.zeek === 'running' &&
                         data.suricata === 'running';
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

    // Filter suggestions by search term
    this.filteredSuggestions = this.suggestions.filter(s =>
      s.label.toLowerCase().includes(term) ||
      s.hint.toLowerCase().includes(term)
    );

    // Add IP search suggestion
    const ipPattern = /^[\d\.:a-f]+$/i;
    if (ipPattern.test(term)) {
      this.filteredSuggestions.unshift({
        label: `Search IP: ${this.searchText}`,
        hint:  'Search in Network Logs',
        route: `/logs?search=${this.searchText}`,
        icon:  '🔍'
      });
    }

    // Add rule search
    if (term.length > 2) {
      this.filteredSuggestions.push({
        label: `Search rules: "${this.searchText}"`,
        hint:  'Find SIGMA rules',
        route: `/rules?search=${this.searchText}`,
        icon:  '⚙️'
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

    // Smart routing based on search term
    if (term.match(/^\d+\.\d+\.\d+\.\d+/) || term.includes(':')) {
      // IP address → Network Logs
      this.router.navigate(['/logs'], {
        queryParams: { search: this.searchText }
      });
    } else if (term.includes('alert') || term.includes('hit')) {
      this.router.navigate(['/alerts']);
    } else if (term.includes('rule') || term.includes('sigma')) {
      this.router.navigate(['/rules']);
    } else if (term.includes('threat') || term.includes('intel') || term.includes('ioc')) {
      this.router.navigate(['/intel']);
    } else if (term.includes('health') || term.includes('status')) {
      this.router.navigate(['/health']);
    } else if (term.includes('live') || term.includes('stream')) {
      this.router.navigate(['/live']);
    } else if (term.includes('map') || term.includes('topology')) {
      this.router.navigate(['/network-map']);
    } else {
      // Default → Network Logs with search
      this.router.navigate(['/logs'], {
        queryParams: { search: this.searchText }
      });
    }

    this.showSuggestions = false;
    this.searchText = '';
  }

  selectSuggestion(suggestion: any) {
    this.router.navigateByUrl(suggestion.route);
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

  viewThreatIntel() {
    this.showNotifications = false;
    this.router.navigate(['/intel']);
  }

  closeSearch() {
    setTimeout(() => {
      this.showSuggestions = false;
      this.cdr.detectChanges();
    }, 200);
  }

  closeNotifications() {
    setTimeout(() => {
      this.showNotifications = false;
      this.cdr.detectChanges();
    }, 160);
  }
}
