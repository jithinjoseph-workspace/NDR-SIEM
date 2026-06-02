import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Api } from '../../services/api/api';
import { Websocket } from '../../services/websocket/websocket';
import { ChartDataService } from '../../services/chart-data/chart-data';
import { Subscription } from 'rxjs';
import {
  LucideAngularModule,
  TrendingUp, TriangleAlert, Shield, Activity, ArrowUpRight, RefreshCw
} from 'lucide-angular';
import { BaseChartDirective } from 'ng2-charts';
import { ChartConfiguration, ChartOptions } from 'chart.js';
import { Router } from '@angular/router';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, BaseChartDirective],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.css',
})
export class Dashboard implements OnInit, OnDestroy {

  // ── Stat card values ──────────────────────────────────────────────────────
  totalEvents    = 0;
  totalHits      = 0;
  eventsLastHour = 0;
  hitsLastHour   = 0;
  zeekEvents     = 0;
  suricataEvents = 0;
  critical = 0;
  high     = 0;
  medium   = 0;
  low      = 0;
  topSrcIps:            any[] = [];
  topDstIps:            any[] = [];
  recentCriticalAlerts: any[] = [];

  // ── Chart state ───────────────────────────────────────────────────────────
  chartLoading = true;   // shows skeleton shimmer
  chartError   = false;  // shows error + retry UI

  /** Cosmetic bar heights for the skeleton shimmer. */
  readonly skeletonBars = ['30%','55%','40%','70%','50%','85%','60%','45%','75%','35%'];

  // ── Icons ─────────────────────────────────────────────────────────────────
  TrendingUpIcon = TrendingUp;
  AlertIcon      = TriangleAlert;
  ShieldIcon     = Shield;
  ActivityIcon   = Activity;
  ArrowIcon      = ArrowUpRight;
  RefreshIcon    = RefreshCw;

  // ── Chart.js config ───────────────────────────────────────────────────────
  public lineChartData: ChartConfiguration<'line'>['data'] = {
    labels: [],
    datasets: [{
      data:                [],
      label:               'Events',
      fill:                true,
      tension:             0.4,
      borderColor:         '#69f6b8',
      backgroundColor:     'rgba(105, 246, 184, 0.1)',
      pointBackgroundColor: '#69f6b8'
    }]
  };

  public lineChartOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      y: { display: false },
      x: {
        grid:  { display: false },
        ticks: { color: '#a4abbf', font: { size: 10 } }
      }
    }
  };

  private subs:           Subscription[] = [];
  private supportInterval: any;   // drives /api/severity + /api/top-ips only

  constructor(
    private api:          Api,
    private ws:           Websocket,
    private chartService: ChartDataService,
    private router:       Router,
    private cdr:          ChangeDetectorRef
  ) {}

  ngOnInit() {
    // Kick off the single background fetch loop in the service.
    // /api/stats is now called ONCE every 30s — result shared with stat cards.
    this.chartService.start();

    // ── Chart: loading state ─────────────────────────────────────────────
    this.subs.push(
      this.chartService.isLoading$.subscribe(loading => {
        this.chartLoading = loading;
        this.cdr.detectChanges();
      })
    );

    // ── Chart: data (SWR pattern) ────────────────────────────────────────
    // Warm start  → BehaviorSubject replays cached value synchronously here,
    //               chart renders on first paint with zero delay.
    // Cold start  → fires once API responds (~1 s), skeleton disappears.
    this.subs.push(
      this.chartService.chart$.subscribe(snapshot => {
        this.chartLoading = false;
        this.chartError   = false;
        this.applyChartSnapshot(snapshot.labels, snapshot.data);
      })
    );

    // ── Stat cards: driven by the same /api/stats fetch as the chart ─────
    // No duplicate network call — service shares the payload via stats$.
    this.subs.push(
      this.chartService.stats$.subscribe(stats => {
        this.totalEvents    = stats.events_total;
        this.totalHits      = stats.hits_total;
        this.eventsLastHour = stats.events_1h;
        this.hitsLastHour   = stats.hits_1h;
        this.zeekEvents     = stats.zeek_events;
        this.suricataEvents = stats.suricata_events;
        this.cdr.detectChanges();
      })
    );

    // ── Chart: error state ───────────────────────────────────────────────
    this.subs.push(
      this.chartService.hasError$.subscribe(hasError => {
        if (hasError) {
          this.chartLoading = false;
          this.chartError   = true;
          this.cdr.detectChanges();
        }
      })
    );

    // ── Supporting data: severity + top IPs every 30 s ───────────────────
    // These have their own endpoints and are not part of /api/stats.
    this.loadSupportingStats();
    this.supportInterval = setInterval(() => this.loadSupportingStats(), 30_000);

    // ── WebSocket: real-time increments ──────────────────────────────────
    this.subs.push(
      this.ws.events$.subscribe(() => {
        this.eventsLastHour++;
        this.totalEvents++;
        this.cdr.detectChanges();
      })
    );

    this.subs.push(
      this.ws.hits$.subscribe(hit => {
        this.totalHits++;
        this.hitsLastHour++;
        const severity = hit.severity?.toUpperCase() || 'LOW';
        if (['CRITICAL', 'HIGH'].includes(severity)) {
          this.recentCriticalAlerts = [{
            severity,
            src_ip: hit.src || hit.suricata?.src || '-',
            dst_ip: hit.dst || hit.suricata?.dst || '-',
            score:  hit.score || 0,
            time:   new Date().toLocaleTimeString(),
          }, ...this.recentCriticalAlerts].slice(0, 5);
        }
        this.cdr.detectChanges();
      })
    );
  }

  // ── Public actions ─────────────────────────────────────────────────────────

  retryChart() {
    this.chartError   = false;
    this.chartLoading = true;
    this.cdr.detectChanges();
    this.chartService.retry();
  }

  exportReport(format: string) { this.api.exportReport(format); }

  openAlerts(queryParams: Record<string, string> = {}) {
    this.router.navigate(['/alerts'], { queryParams });
  }

  openNetworkMap() { this.router.navigate(['/network-map']); }

  // ── Private helpers ────────────────────────────────────────────────────────

  /**
   * Fetches severity breakdown and top IPs — the only remaining periodic
   * API calls in this component. /api/stats is handled entirely by
   * ChartDataService to avoid duplicate requests.
   */
  private loadSupportingStats() {
    this.api.getSeverity().subscribe(data => {
      this.critical = data.critical || 0;
      this.high     = data.high     || 0;
      this.medium   = data.medium   || 0;
      this.low      = data.low      || 0;
      this.cdr.detectChanges();
    });

    this.api.getTopIps().subscribe(data => {
      this.topSrcIps = data.top_src_ips || [];
      this.topDstIps = data.top_dst_ips || [];
      this.cdr.detectChanges();
    });
  }

  private applyChartSnapshot(labels: string[], data: number[]) {
    this.lineChartData = {
      labels: [...labels],
      datasets: [{
        data:                [...data],
        label:               'Events',
        fill:                true,
        tension:             0.4,
        borderColor:         '#69f6b8',
        backgroundColor:     'rgba(105, 246, 184, 0.1)',
        pointBackgroundColor: '#69f6b8'
      }]
    };
    this.cdr.detectChanges();
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
    if (this.supportInterval) clearInterval(this.supportInterval);
  }
}
