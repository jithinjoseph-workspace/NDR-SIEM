import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Api } from '../../services/api/api';
import { Websocket } from '../../services/websocket/websocket';
import { Subscription } from 'rxjs';
import { LucideAngularModule, ShieldAlert, ExternalLink, Filter, MoreHorizontal } from 'lucide-angular';

@Component({
  selector: 'app-alerts',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './alerts.html',
  styleUrl: './alerts.css'
})
export class Alerts implements OnInit, OnDestroy {
  alerts: any[] = [];
  loading: boolean = true;

  ShieldAlertIcon = ShieldAlert;
  ExternalLinkIcon = ExternalLink;
  FilterIcon = Filter;
  MoreIcon = MoreHorizontal;

  private subs: Subscription[] = [];

  constructor(
    private api: Api,
    private ws: Websocket,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.loadAlerts();

    // Real-time — add new hit to top of list via WebSocket
    this.subs.push(
      this.ws.hits$.subscribe(hit => {
        this.alerts.unshift({
          severity:    hit.severity?.toUpperCase() || 'LOW',
          source:      `${hit.src || hit.suricata?.src || '-'} → ${hit.dst || hit.suricata?.dst || '-'}`,
          description: hit.sigma_hits?.join(', ') || hit.tags?.join(', ') || 'Correlation hit',
          time:        new Date().toLocaleTimeString(),
          score:       hit.score,
          community_id: hit.cid,
        });
        // Keep max 100 alerts
        if (this.alerts.length > 100) this.alerts.pop();
        this.cdr.detectChanges();
      })
    );
  }

  loadAlerts() {
    this.loading = true;
    this.api.getAlerts().subscribe({
      next: (data: any[]) => {
        this.alerts = data.map(hit => ({
          severity:     hit.severity?.toUpperCase() || 'LOW',
          source:       `${hit.src_ip || '-'} → ${hit.dst_ip || '-'}`,
          description:  hit.sigma_hits?.join(', ') || 'Correlation hit',
          time:         new Date(hit.timestamp * 1000).toLocaleString(),
          score:        hit.score,
          threat_intel: hit.threat_intel,
          src_country:  hit.src_country,
          dst_country:  hit.dst_country,
        }));
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  getSeverityClass(severity: string) {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'bg-red-500/10 text-red-400 border-red-500/20';
      case 'HIGH':     return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
      case 'MEDIUM':   return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
      default:         return 'bg-primary/10 text-primary border-primary/20';
    }
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
  }
}