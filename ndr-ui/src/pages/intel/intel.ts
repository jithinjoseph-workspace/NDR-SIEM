import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';
import { Notifications, ThreatNotification } from '../../services/notifications/notifications';
import { Subscription } from 'rxjs';
import { LucideAngularModule, Search, ShieldCheck, CircleAlert, RefreshCw, Hash, Bell, Plus } from 'lucide-angular';
import { AuthService } from '../../services/auth/auth';
import { SensorScopeBanner } from '../../components/sensor-scope-banner/sensor-scope-banner';

@Component({
  selector: 'app-intel',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, FormsModule, SensorScopeBanner],
  templateUrl: './intel.html',
  styleUrl: './intel.css'
})
export class Intel implements OnInit, OnDestroy {
  totalMaliciousIps: number = 0;
  source: string = '';
  detectedInNetwork: any[] = [];
  loading: boolean = true;
  searching: boolean = false;
  searchIp: string = '';
  lookupResult: any = null;
  lastRefresh: string = '';

  // Real-time alerts
  liveAlerts: ThreatNotification[] = [];
  newAlertCount: number = 0;

  SearchIcon      = Search;
  ShieldCheckIcon = ShieldCheck;
  AlertIcon       = CircleAlert;
  RefreshIcon     = RefreshCw;
  HashIcon        = Hash;
  BellIcon        = Bell;
  PlusIcon        = Plus;

  // Manual IOC add
  addIocType: string = 'ip';
  addIocValue: string = '';
  addIocLoading: boolean = false;
  addIocResult: { status: string; message: string } | null = null;

  private subs: Subscription[] = [];
  private processedAlertHits = new Map<string, number>();

  /** Sensor IDs this user is scoped to (from JWT). */
  sensorIds: string[] = [];

  constructor(
    private api: Api,
    private notifications: Notifications,
    private cdr: ChangeDetectorRef,
    private auth: AuthService
  ) {}

  ngOnInit() {
    this.sensorIds = this.auth.getSensorIds();
    this.loadIntel();

    this.subs.push(
      this.notifications.alerts$.subscribe(alerts => {
        this.liveAlerts = alerts.slice(0, 20);
        this.syncDetectedNetworkAlerts(alerts);
        this.cdr.detectChanges();
      })
    );

    this.subs.push(
      this.notifications.unreadCount$.subscribe(count => {
        this.newAlertCount = count;
        this.cdr.detectChanges();
      })
    );
  }

  loadIntel() {
    this.loading = true;
    this.api.getThreatIntel().subscribe({
      next: (data: any) => {
        this.totalMaliciousIps = data.total_malicious_ips || 0;
        this.source            = data.source || 'abuse.ch';
        this.detectedInNetwork = data.detected_in_network || [];
        this.lastRefresh       = data.last_refresh
          ? `Last updated: ${data.last_refresh} · ${data.refresh_interval || 'Every 60 min'}`
          : (data.refresh_interval || 'Every 60 minutes');
        this.syncDetectedNetworkAlerts(this.liveAlerts);
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  lookupIoc() {
    if (!this.searchIp.trim()) return;
    this.searching = true;
    this.lookupResult = null;
    this.api.lookupIoc(this.searchIp.trim()).subscribe({
      next: (data: any) => {
        this.lookupResult = data;
        this.searching = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.searching = false;
        this.cdr.detectChanges();
      }
    });
  }

  clearAlerts() {
    this.notifications.clearAlerts();
    this.cdr.detectChanges();
  }

  addManualIoc() {
    if (!this.addIocValue.trim()) return;
    this.addIocLoading = true;
    this.addIocResult = null;
    this.api.addManualIoc(this.addIocType, this.addIocValue.trim()).subscribe({
      next: (res: any) => {
        this.addIocResult = { status: 'ok', message: res.message || `${res.type} IOC added` };
        this.addIocValue = '';
        this.addIocLoading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.addIocResult = { status: 'error', message: 'Failed to add IOC' };
        this.addIocLoading = false;
        this.cdr.detectChanges();
      }
    });
  }

  private syncDetectedNetworkAlerts(alerts: ThreatNotification[]) {
    for (const alert of alerts) {
      const key = alert.id;
      const existing = this.detectedInNetwork.find(d => d.src_ip === alert.src_ip);
      const processedHits = this.processedAlertHits.get(key) || 0;
      const newHits = Math.max((alert.hits || 1) - processedHits, 0);

      if (newHits === 0) {
        continue;
      }

      this.processedAlertHits.set(key, alert.hits || 1);

      if (existing) {
        existing.hits += newHits;
        existing.last_seen = Math.floor(Date.now() / 1000);
      } else {
        this.detectedInNetwork.unshift({
          src_ip: alert.src_ip,
          dst_ip: alert.dst_ip,
          hits: alert.hits || 1,
          last_seen: Math.floor(Date.now() / 1000),
        });
      }
    }
  }

  getTimestamp(ts: number): string {
    if (!ts) return '-';
    return new Date(ts * 1000).toLocaleString();
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
  }
}
