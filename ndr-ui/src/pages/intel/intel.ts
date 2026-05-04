import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';
import { Websocket } from '../../services/websocket/websocket';
import { Subscription } from 'rxjs';
import { LucideAngularModule, Search, ShieldCheck, AlertCircle, RefreshCw, Hash, Bell } from 'lucide-angular';

@Component({
  selector: 'app-intel',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, FormsModule],
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
  liveAlerts: any[] = [];
  newAlertCount: number = 0;

  SearchIcon      = Search;
  ShieldCheckIcon = ShieldCheck;
  AlertIcon       = AlertCircle;
  RefreshIcon     = RefreshCw;
  HashIcon        = Hash;
  BellIcon        = Bell;

  private subs: Subscription[] = [];

  constructor(
    private api: Api,
    private ws: Websocket,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.loadIntel();

    // Real-time threat intel alerts via WebSocket
    this.subs.push(
      this.ws.hits$.subscribe((hit: any) => {
        if (!hit.threat_intel) return;

        // New malicious IP detected in network!
        const alert = {
          time:      new Date().toLocaleTimeString(),
          src_ip:    hit.src    || hit.suricata?.src || '-',
          dst_ip:    hit.dst    || hit.suricata?.dst || '-',
          severity:  hit.severity || 'HIGH',
          score:     hit.score  || 0,
          tags:      hit.tags   || [],
        };

        // Add to live alerts
        this.liveAlerts.unshift(alert);
        if (this.liveAlerts.length > 20) this.liveAlerts.pop();
        this.newAlertCount++;

        // Also add to detected in network
        const existing = this.detectedInNetwork
            .find(d => d.src_ip === alert.src_ip);
        if (existing) {
          existing.hits++;
          existing.last_seen = Math.floor(Date.now() / 1000);
        } else {
          this.detectedInNetwork.unshift({
            src_ip:    alert.src_ip,
            dst_ip:    alert.dst_ip,
            hits:      1,
            last_seen: Math.floor(Date.now() / 1000),
          });
        }

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
        this.lastRefresh       = data.last_refresh || '';
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
    this.liveAlerts = [];
    this.newAlertCount = 0;
    this.cdr.detectChanges();
  }

  getTimestamp(ts: number): string {
    if (!ts) return '-';
    return new Date(ts * 1000).toLocaleString();
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
  }
}