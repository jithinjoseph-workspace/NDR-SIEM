import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Api } from '../../services/api/api';
import { Websocket } from '../../services/websocket/websocket';
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
  chartLabels: string[] = [];
  chartData: number[] = [];

  private subs: Subscription[] = [];
  private refreshInterval: any;
  private static chartInitialized: boolean = false;
  private static savedChartData: number[] = [];
  private static savedTotalEvents: number = 0;
  private static savedTotalHits: number = 0;
  private static savedTenantId: string = '';

  static clearCache() {
    Dashboard.chartInitialized = false;
    Dashboard.savedChartData = [];
    Dashboard.savedTotalEvents = 0;
    Dashboard.savedTotalHits = 0;
    Dashboard.savedTenantId = '';
  }

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
    private cdr: ChangeDetectorRef
  ) { }

  ngOnInit() {
    // Clear cache if a different tenant has logged in
    const currentUser = JSON.parse(localStorage.getItem('ndr_user') || '{}');
    const currentTenant = currentUser?.tenant_id || '';
    if (Dashboard.savedTenantId && Dashboard.savedTenantId !== currentTenant) {
      Dashboard.clearCache();
    }
    Dashboard.savedTenantId = currentTenant;

    // Restore saved state if exists
    this.chartLabels = ['', '', '', '', '', ''];
    if (Dashboard.savedChartData.length > 0) {
      this.chartData = [...Dashboard.savedChartData];
      this.totalEvents = Dashboard.savedTotalEvents;
      this.totalHits = Dashboard.savedTotalHits;
    } else {
      this.chartData = [0, 0, 0, 0, 0, 0];
    }
    this.updateChartData();
    this.loadAllStats();

    // Refresh every 30 seconds
    this.refreshInterval = setInterval(() => {
      this.loadAllStats();
      this.addChartPoint();  // add point every 30s

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

      if (!Dashboard.chartInitialized) {
        this.chartData = [
          this.eventsLastHour, this.eventsLastHour, this.eventsLastHour,
          this.eventsLastHour, this.eventsLastHour, this.eventsLastHour
        ];
        Dashboard.chartInitialized = true;
        this.updateChartData();
      }

      // Persist state for same-tenant navigation
      Dashboard.savedChartData = [...this.chartData];
      Dashboard.savedTotalEvents = this.totalEvents;
      Dashboard.savedTotalHits = this.totalHits;

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

  addChartPoint() {
    const now = new Date().toLocaleTimeString('en-US', {
      hour: '2-digit', minute: '2-digit'
    });
    if (this.chartLabels.length >= 10) {
      this.chartLabels.shift();
      this.chartData.shift();
    }
    this.chartLabels.push(now);
    this.chartData.push(this.eventsLastHour);
    this.updateChartData();
    Dashboard.savedChartData = [...this.chartData];
  }

  updateChartData() {
    this.lineChartData = {
      labels: [...this.chartLabels],
      datasets: [{
        data: [...this.chartData],
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
