import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Api } from '../../services/api/api';
import { Websocket } from '../../services/websocket/websocket';
import { ChartDataService } from '../../services/chart-data/chart-data';
import { Subscription } from 'rxjs';
import { LucideAngularModule, TrendingUp, TriangleAlert, Shield, Activity, ArrowUpRight } from 'lucide-angular';
import { BaseChartDirective } from 'ng2-charts';
import { ChartConfiguration, ChartOptions } from 'chart.js';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, BaseChartDirective],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.css',
})
export class Dashboard implements OnInit, OnDestroy {
  totalEvents: number = 0;
  totalHits: number = 0;
  eventsLastHour: number = 0;
  hitsLastHour: number = 0;
  zeekEvents: number = 0;
  suricataEvents: number = 0;
  critical: number = 0;
  high: number = 0;
  medium: number = 0;
  low: number = 0;
  topSrcIps: any[] = [];
  topDstIps: any[] = [];

  private subs: Subscription[] = [];
  private refreshInterval: any;

  TrendingUpIcon = TrendingUp;
  AlertIcon = TriangleAlert;
  ShieldIcon = Shield;
  ActivityIcon = Activity;
  ArrowIcon = ArrowUpRight;

  public lineChartData: ChartConfiguration<'line'>['data'] = {
    labels: [],
    datasets: [{
      data: [],
      label: 'Events',
      fill: true,
      tension: 0.4,
      borderColor: '#69f6b8',
      backgroundColor: 'rgba(105, 246, 184, 0.1)',
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
        grid: { display: false },
        ticks: { color: '#a4abbf', font: { size: 10 } }
      }
    }
  };

  constructor(
    private api: Api,
    private ws: Websocket,
    private chartService: ChartDataService,
    private cdr: ChangeDetectorRef
  ) { }

  ngOnInit() {
    // Ensure the chart data service is running (idempotent)
    this.chartService.start();

    // Immediately load the persisted chart data (survives tab switches)
    this.syncChartFromService();

    // Load dashboard stats
    this.loadAllStats();

    // Refresh stats & re-sync chart every 30 seconds
    this.refreshInterval = setInterval(() => {
      this.loadAllStats();
      this.syncChartFromService();
    }, 30000);

    // WebSocket real-time updates
    this.subs.push(
      this.ws.events$.subscribe(() => {
        this.eventsLastHour++;
        this.totalEvents++;
        this.cdr.detectChanges();
      })
    );

    this.subs.push(
      this.ws.hits$.subscribe(() => {
        this.totalHits++;
        this.hitsLastHour++;
        this.cdr.detectChanges();
      })
    );
  }

  exportReport(format: string) {
    this.api.exportReport(format);
  }

  loadAllStats() {
    this.api.getStats().subscribe(data => {
      this.totalEvents = data.events_total || 0;
      this.totalHits = data.hits_total || 0;
      this.eventsLastHour = data.events_1h || 0;
      this.hitsLastHour = data.hits_1h || 0;
      this.zeekEvents = data.zeek_events || 0;
      this.suricataEvents = data.suricata_events || 0;
      this.cdr.detectChanges();
    });

    this.api.getSeverity().subscribe(data => {
      this.critical = data.critical || 0;
      this.high = data.high || 0;
      this.medium = data.medium || 0;
      this.low = data.low || 0;
      this.cdr.detectChanges();
    });

    this.api.getTopIps().subscribe(data => {
      this.topSrcIps = data.top_src_ips || [];
      this.topDstIps = data.top_dst_ips || [];
      this.cdr.detectChanges();
    });
  }

  /** Pull the latest chart snapshot from the persistent service */
  private syncChartFromService() {
    const snapshot = this.chartService.getSnapshot();
    this.lineChartData = {
      labels: snapshot.labels,
      datasets: [{
        data: snapshot.data,
        label: 'Events',
        fill: true,
        tension: 0.4,
        borderColor: '#69f6b8',
        backgroundColor: 'rgba(105, 246, 184, 0.1)',
        pointBackgroundColor: '#69f6b8'
      }]
    };
    this.cdr.detectChanges();
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
    if (this.refreshInterval) clearInterval(this.refreshInterval);
  }
}
