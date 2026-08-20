import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../../services/api/api';
import { LucideAngularModule, RotateCcw, Play, RefreshCw, ChevronDown, ChevronRight } from 'lucide-angular';

interface RetroScan {
  id:           string;
  rule_sid:     number;
  hours_back:   number;
  status:       'pending' | 'running' | 'done' | 'failed';
  started_at:   string;
  completed_at: string | null;
  match_count:  number;
  matches?:     any[];
}

@Component({
  selector: 'app-retrospective',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './retrospective.html',
  styleUrl: './retrospective.scss',
})
export class Retrospective implements OnInit {
  RetroIcon     = RotateCcw;
  PlayIcon      = Play;
  RefreshIcon   = RefreshCw;
  ChevronDown   = ChevronDown;
  ChevronRight  = ChevronRight;

  scans: RetroScan[]     = [];
  selectedScan: RetroScan | null = null;
  selectedMatches: any[] = [];

  loading     = false;
  scanning    = false;
  error       = '';
  success     = '';

  ruleSid     = '';
  ruleContent = '';
  hoursBack   = 24;

  hoursOptions = [24, 48, 72, 168];

  constructor(private api: Api, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void { this.loadScans(); }

  loadScans(): void {
    this.loading = true;
    this.api.listRetroScans().subscribe({
      next: (r: any) => {
        this.scans   = (r.scans ?? []).sort((a: RetroScan, b: RetroScan) =>
          new Date(b.started_at).getTime() - new Date(a.started_at).getTime());
        this.loading = false;
        this.cdr.markForCheck();
      },
      error: (e: any) => {
        this.error   = e?.error?.message ?? 'Failed to load scans';
        this.loading = false;
        this.cdr.markForCheck();
      },
    });
  }

  startScan(): void {
    const sid = parseInt(this.ruleSid, 10) || 0;
    if (sid === 0 && !this.ruleContent.trim()) {
      this.error = 'Enter a Rule SID or a keyword to search';
      return;
    }
    this.scanning = true;
    this.error    = '';
    this.api.startRetroScan(sid, this.ruleContent, this.hoursBack).subscribe({
      next: (r: any) => {
        this.scanning = false;
        this.success  = `Scan started (ID: ${r.scan_id})`;
        this.loadScans();
        setTimeout(() => { this.success = ''; this.cdr.markForCheck(); }, 5000);
      },
      error: (e: any) => {
        this.error    = e?.error?.message ?? 'Failed to start scan';
        this.scanning = false;
        this.cdr.markForCheck();
      },
    });
  }

  viewScan(scan: RetroScan): void {
    if (this.selectedScan?.id === scan.id) {
      this.selectedScan   = null;
      this.selectedMatches = [];
      return;
    }
    this.selectedScan = scan;
    if (scan.status === 'done') {
      this.api.getRetroScan(scan.id).subscribe({
        next: (r: any) => {
          this.selectedMatches = r.scan?.matches ?? [];
          this.cdr.markForCheck();
        },
        error: () => { this.selectedMatches = []; },
      });
    }
  }

  statusClass(status: string): string {
    return {
      pending: 'badge-pending',
      running: 'badge-running',
      done:    'badge-done',
      failed:  'badge-failed',
    }[status] ?? 'badge-pending';
  }
}
