import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';
import { LucideAngularModule, Search, ShieldCheck, AlertCircle, RefreshCw, Hash } from 'lucide-angular';

@Component({
  selector: 'app-intel',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, FormsModule],
  templateUrl: './intel.html',
  styleUrl: './intel.css'
})
export class Intel implements OnInit {
  totalMaliciousIps: number = 0;
  source: string = '';
  detectedInNetwork: any[] = [];
  loading: boolean = true;
  searching: boolean = false;
  searchIp: string = '';
  lookupResult: any = null;
  lastRefresh: string = '';

  SearchIcon     = Search;
  ShieldCheckIcon = ShieldCheck;
  AlertIcon      = AlertCircle;
  RefreshIcon    = RefreshCw;
  HashIcon       = Hash;

  constructor(private api: Api, private cdr: ChangeDetectorRef) {}

  ngOnInit() {
    this.loadIntel();
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

  getTimestamp(ts: number): string {
    if (!ts) return '-';
    return new Date(ts * 1000).toLocaleString();
  }
}