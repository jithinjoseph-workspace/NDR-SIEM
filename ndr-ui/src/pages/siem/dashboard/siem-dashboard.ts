import { Component, OnInit, OnDestroy, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { RouterModule } from '@angular/router';
import { interval, Subscription } from 'rxjs';
import { startWith, switchMap } from 'rxjs/operators';
import {
  LucideAngularModule,
  Activity, AlertTriangle, CheckCircle, Database,
  Radio, TrendingUp, XCircle, Zap
} from 'lucide-angular';

interface SiemStats {
  eps_current:      number;
  logs_today:       number;
  logs_last_hour:   number;
  parse_errors:     number;
  active_sources:   number;
  total_sources:    number;
  kafka_lag:        number;
}

interface SourceHealth {
  source_id:   string;
  name:        string;
  source_type: string;
  status:      string;
  last_seen_at: string;
  eps:          number;
}

@Component({
  selector: 'app-siem-dashboard',
  standalone: true,
  imports: [CommonModule, RouterModule, LucideAngularModule],
  templateUrl: './siem-dashboard.html',
  styleUrl: './siem-dashboard.css',
})
export class SiemDashboard implements OnInit, OnDestroy {

  // ── Stat cards ────────────────────────────────────────────────────────────
  eps          = signal(0);
  logsToday    = signal(0);
  logsLastHour = signal(0);
  parseErrors  = signal(0);
  activeSources = signal(0);
  totalSources  = signal(0);
  kafkaLag      = signal(0);

  // ── Source health table ───────────────────────────────────────────────────
  sources    = signal<SourceHealth[]>([]);
  loading    = signal(true);
  error      = signal<string | null>(null);

  // ── Icons ─────────────────────────────────────────────────────────────────
  readonly ActivityIcon    = Activity;
  readonly AlertIcon       = AlertTriangle;
  readonly CheckIcon       = CheckCircle;
  readonly DatabaseIcon    = Database;
  readonly RadioIcon       = Radio;
  readonly TrendIcon       = TrendingUp;
  readonly ErrorIcon       = XCircle;
  readonly ZapIcon         = Zap;

  private pollSub?: Subscription;

  constructor(private http: HttpClient) {}

  ngOnInit() {
    this.pollSub = interval(15_000).pipe(
      startWith(0),
      switchMap(() => this.http.get<{ stats: SiemStats; sources: SourceHealth[] }>('/api/siem/dashboard'))
    ).subscribe({
      next: res => {
        const s = res.stats;
        this.eps.set(s.eps_current);
        this.logsToday.set(s.logs_today);
        this.logsLastHour.set(s.logs_last_hour);
        this.parseErrors.set(s.parse_errors);
        this.activeSources.set(s.active_sources);
        this.totalSources.set(s.total_sources);
        this.kafkaLag.set(s.kafka_lag);
        this.sources.set(res.sources ?? []);
        this.loading.set(false);
        this.error.set(null);
      },
      error: () => {
        this.loading.set(false);
        this.error.set('Failed to load SIEM dashboard');
      }
    });
  }

  ngOnDestroy() { this.pollSub?.unsubscribe(); }

  statusClass(s: string): string {
    return ({ active: 'status-ok', paused: 'status-warn', error: 'status-err' } as any)[s] ?? 'status-warn';
  }

  sourceTypeLabel(t: string): string {
    return ({ wec: 'WEC', syslog: 'Syslog', firewall_cef: 'CEF', generic: 'REST', aws_cloudtrail: 'AWS' } as any)[t] ?? t;
  }

  formatNum(n: number): string {
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
    if (n >= 1_000)     return (n / 1_000).toFixed(1) + 'K';
    return n.toString();
  }
}
