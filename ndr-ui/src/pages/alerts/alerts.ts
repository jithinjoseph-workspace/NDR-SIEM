import { Component, OnDestroy, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Api } from '../../services/api/api';
import { Websocket } from '../../services/websocket/websocket';
import { Subscription } from 'rxjs';
import { ActivatedRoute } from '@angular/router';
import {
  LucideAngularModule,
  AlertTriangle,
  ExternalLink,
  MoreHorizontal,
  RefreshCw,
  ShieldAlert,
} from 'lucide-angular';

@Component({
  selector: 'app-alerts',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './alerts.html',
  styleUrl: './alerts.css',
})
export class Alerts implements OnInit, OnDestroy {
  alerts: any[] = [];
  private allAlerts: any[] = [];
  loading: boolean = true;
  activeSeverity: string = '';
  priorityOnly: boolean = false;

  ShieldAlertIcon = ShieldAlert;
  AlertTriangleIcon = AlertTriangle;
  ExternalLinkIcon = ExternalLink;
  MoreIcon = MoreHorizontal;
  RefreshIcon = RefreshCw;

  private subs: Subscription[] = [];

  constructor(
    private api: Api,
    private ws: Websocket,
    private route: ActivatedRoute,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.subs.push(
      this.route.queryParamMap.subscribe(params => {
        this.activeSeverity = params.get('severity')?.toUpperCase() || '';
        this.priorityOnly = params.get('priority') === 'true';
        this.applyFilters();
        this.cdr.detectChanges();
      })
    );

    this.loadAlerts();

    // Real-time - add new hit to top of list via WebSocket
    this.subs.push(
      this.ws.hits$.subscribe(hit => {
        const alert = {
          severity: hit.severity?.toUpperCase() || 'LOW',
          source: `${hit.src || hit.suricata?.src || '-'} -> ${hit.dst || hit.suricata?.dst || '-'}`,
          description: hit.sigma_hits?.join(', ') || hit.tags?.join(', ') || 'Correlation hit',
          time: new Date().toLocaleTimeString(),
          score: hit.score,
          community_id: hit.cid,
        };
        this.allAlerts.unshift(alert);
        // Keep max 100 alerts
        if (this.allAlerts.length > 100) this.allAlerts.pop();
        this.applyFilters();
        this.cdr.detectChanges();
      })
    );
  }

  loadAlerts() {
    this.loading = true;
    this.api.getAlerts().subscribe({
      next: (data: any[]) => {
        this.allAlerts = data.map(hit => ({
          severity: hit.severity?.toUpperCase() || 'LOW',
          source: `${hit.src_ip || '-'} -> ${hit.dst_ip || '-'}`,
          description: hit.sigma_hits?.join(', ') || 'Correlation hit',
          time: new Date(hit.timestamp * 1000).toLocaleString(),
          score: hit.score,
          threat_intel: hit.threat_intel,
          src_country: hit.src_country,
          dst_country: hit.dst_country,
        }));
        this.applyFilters();
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loading = false;
        this.cdr.detectChanges();
      },
    });
  }

  private applyFilters() {
    this.alerts = this.allAlerts.filter(alert => {
      const severity = alert.severity?.toUpperCase();
      if (this.activeSeverity && severity !== this.activeSeverity) return false;
      if (this.priorityOnly && !['CRITICAL', 'HIGH'].includes(severity)) return false;
      return true;
    });
  }

  get totalAlerts() {
    return this.alerts.length;
  }

  get priorityAlerts() {
    return this.alerts.filter(alert => ['CRITICAL', 'HIGH'].includes(alert.severity?.toUpperCase())).length;
  }

  get mediumAlerts() {
    return this.alerts.filter(alert => alert.severity?.toUpperCase() === 'MEDIUM').length;
  }

  get intelAlerts() {
    return this.alerts.filter(alert => alert.threat_intel).length;
  }

  getScoreClass(score: number) {
    if (score > 70) return 'score-high';
    if (score > 40) return 'score-medium';
    return 'score-low';
  }

  getSeverityClass(severity: string) {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-400 border-red-500/20';
      case 'HIGH':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
      default:
        return 'bg-primary/10 text-primary border-primary/20';
    }
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
  }
}
