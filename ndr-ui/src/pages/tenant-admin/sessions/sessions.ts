import { Component, Input, OnInit, ChangeDetectionStrategy, signal, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import {
  LucideAngularModule,
  Activity, RefreshCw, Loader, XCircle, AlertCircle, Server,
} from 'lucide-angular';
import { Api } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';

@Component({
  selector: 'app-sessions',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './sessions.html',
  styleUrl: './sessions.css',
})
export class Sessions implements OnInit {
  @Input() tenantId = '';

  ActivityIcon    = Activity;
  RefreshCwIcon   = RefreshCw;
  LoaderIcon      = Loader;
  XCircleIcon     = XCircle;
  AlertCircleIcon = AlertCircle;
  ServerIcon      = Server;

  readonly activeSessions         = signal<any[]>([]);
  readonly sessionsLoading        = signal(false);
  readonly sessionsGrouped        = signal<Record<string, any[]>>({});
  readonly forceLogoutConfirmUser   = signal('');
  readonly forceLogoutDeviceKey     = signal(''); // "{username}|{ip}|{device}"
  readonly message                  = signal('');
  readonly messageType              = signal<'success' | 'error'>('success');

  trackByUsername(_: number, name: string) { return name; }
  trackByIndex(i: number)                  { return i; }

  constructor(private api: Api, private auth: AuthService) {}

  ngOnInit() {
    if (!this.tenantId) {
      this.tenantId = this.auth.getUser()?.tenant_id || 'default';
    }
    this.loadActiveSessions();
  }

  loadActiveSessions() {
    this.sessionsLoading.set(true);
    this.api.getActiveSessions().subscribe({
      next: (data: any) => {
        const sessions: any[] = data.sessions || [];
        const grouped: Record<string, any[]> = {};
        for (const s of sessions) {
          if (!grouped[s.username]) grouped[s.username] = [];
          grouped[s.username].push(s);
        }
        this.activeSessions.set(sessions);
        this.sessionsGrouped.set(grouped);
        this.sessionsLoading.set(false);
      },
      error: () => { this.sessionsLoading.set(false); }
    });
  }

  sessionUsernames(): string[] {
    return Object.keys(this.sessionsGrouped()).sort();
  }

  groupedDevices(username: string): { device: string; ip: string; latestTime: string; count: number }[] {
    const sessions = this.sessionsGrouped()[username] || [];
    const map: Record<string, { device: string; ip: string; latestTime: string; count: number }> = {};
    for (const s of sessions) {
      const key = `${s.device}|${s.ip}`;
      if (!map[key]) {
        map[key] = { device: s.device || 'Unknown', ip: s.ip || '—', latestTime: s.login_time, count: 0 };
      }
      map[key].count++;
      if (s.login_time > map[key].latestTime) map[key].latestTime = s.login_time;
    }
    return Object.values(map).sort((a, b) => b.latestTime.localeCompare(a.latestTime));
  }

  promptForceLogout(username: string) {
    this.forceLogoutConfirmUser.set(username);
  }

  cancelForceLogout() {
    this.forceLogoutConfirmUser.set('');
  }

  promptForceLogoutDevice(username: string, ip: string, device: string) {
    this.forceLogoutDeviceKey.set(`${username}|${ip}|${device}`);
  }

  cancelForceLogoutDevice() {
    this.forceLogoutDeviceKey.set('');
  }

  confirmForceLogoutDevice(username: string, ip: string, device: string) {
    this.api.forceLogoutDevice(username, ip, device).subscribe({
      next: (data: any) => {
        this.forceLogoutDeviceKey.set('');
        this.showMessage(`Signed out ${device} (${ip}) — ${data.sessions_terminated} session(s) terminated`, 'success');
        this.loadActiveSessions();
      },
      error: () => {
        this.showMessage('Failed to sign out device', 'error');
        this.forceLogoutDeviceKey.set('');
      },
    });
  }

  confirmForceLogout(username: string) {
    this.api.forceLogoutUser(username).subscribe({
      next: (data: any) => {
        this.forceLogoutConfirmUser.set('');
        this.showMessage(`${username} signed out from ${data.sessions_terminated} device(s)`, 'success');
        this.loadActiveSessions();
      },
      error: () => {
        this.showMessage('Failed to sign out user', 'error');
        this.forceLogoutConfirmUser.set('');
      }
    });
  }

  formatLoginTime(ts: string): string {
    if (!ts) return '—';
    return new Date(parseInt(ts, 10) * 1000).toLocaleString();
  }

  showMessage(message: string, type: 'success' | 'error') {
    this.message.set(message);
    this.messageType.set(type);
    setTimeout(() => this.message.set(''), 5000);
  }
}
