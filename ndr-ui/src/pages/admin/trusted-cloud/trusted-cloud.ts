import { Component, OnInit, OnDestroy, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  RefreshCw, ShieldCheck, Cloud, Sparkles, CheckCircle2, Trash2, Plus, Clock, Activity, Zap, Check, X, ShieldAlert
} from 'lucide-angular';
import { Api } from '../../../services/api/api';

@Component({
  selector: 'app-trusted-cloud',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './trusted-cloud.html',
  styleUrl: './trusted-cloud.css',
})
export class TrustedCloud implements OnInit, OnDestroy {
  Math = Math;

  RefreshIcon     = RefreshCw;
  ShieldIcon      = ShieldCheck;
  CloudIcon       = Cloud;
  SparklesIcon    = Sparkles;
  CheckIcon       = CheckCircle2;
  TrashIcon       = Trash2;
  PlusIcon        = Plus;
  ClockIcon       = Clock;
  ActivityIcon    = Activity;
  ZapIcon         = Zap;
  ApproveIcon     = Check;
  RejectIcon      = X;
  ShieldAlertIcon = ShieldAlert;

  trustedCloud: { keywords: string[]; domains: string[]; suggestions: { org: string; hits: number }[] } =
    { keywords: [], domains: [], suggestions: [] };

  newKeyword         = '';
  newDomain          = '';
  trustedCloudSaving = false;
  trustedCloudSaved  = false;
  loadingTrustedCloud = false;

  currentTime = '';
  currentDate = '';
  private clockTimer: any = null;

  constructor(private api: Api, private cdr: ChangeDetectorRef) {}

  get totalCloudRules(): number {
    return this.trustedCloud.keywords.length + this.trustedCloud.domains.length;
  }

  get aiSuggestionsCount(): number {
    return this.trustedCloud.suggestions.length;
  }

  get totalHitsSuppressed(): number {
    return this.trustedCloud.suggestions.reduce((acc, s) => acc + (s.hits || 0), 0);
  }

  private updateClock() {
    const now = new Date();
    this.currentTime = now.toLocaleTimeString('en-US', { hour12: false });
    this.currentDate = now.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' });
    this.cdr.detectChanges();
  }

  ngOnInit() {
    this.updateClock();
    this.clockTimer = setInterval(() => this.updateClock(), 1000);
    this.loadTrustedCloud();
  }

  ngOnDestroy() {
    if (this.clockTimer) clearInterval(this.clockTimer);
  }

  loadTrustedCloud() {
    this.loadingTrustedCloud = true;
    this.api.getTrustedCloudSettings().subscribe({
      next: (data: any) => { this.trustedCloud = data; this.loadingTrustedCloud = false; this.cdr.detectChanges(); },
      error: () => { this.loadingTrustedCloud = false; this.cdr.detectChanges(); },
    });
  }

  addKeyword() {
    const kw = this.newKeyword.trim().toUpperCase();
    if (kw && !this.trustedCloud.keywords.includes(kw)) this.trustedCloud.keywords.push(kw);
    this.newKeyword = '';
  }

  removeKeyword(kw: string) { this.trustedCloud.keywords = this.trustedCloud.keywords.filter(k => k !== kw); }

  addDomain() {
    const d = this.newDomain.trim().toLowerCase();
    if (d && !this.trustedCloud.domains.includes(d)) this.trustedCloud.domains.push(d);
    this.newDomain = '';
  }

  removeDomain(d: string) { this.trustedCloud.domains = this.trustedCloud.domains.filter(x => x !== d); }

  saveTrustedCloud() {
    this.trustedCloudSaving = true; this.trustedCloudSaved = false;
    this.api.updateTrustedCloudSettings({
      keywords: this.trustedCloud.keywords, domains: this.trustedCloud.domains,
    }).subscribe({
      next: () => {
        this.trustedCloudSaving = false; this.trustedCloudSaved = true;
        setTimeout(() => { this.trustedCloudSaved = false; this.cdr.detectChanges(); }, 3000);
        this.cdr.detectChanges();
      },
      error: () => { this.trustedCloudSaving = false; this.cdr.detectChanges(); },
    });
  }

  approveSuggestion(org: string) {
    this.api.approveTrustedCloudSuggestion(org).subscribe({
      next: () => {
        this.trustedCloud.suggestions = this.trustedCloud.suggestions.filter(s => s.org !== org);
        if (!this.trustedCloud.keywords.includes(org.split(' ')[0])) this.trustedCloud.keywords.push(org.split(' ')[0]);
        this.cdr.detectChanges();
      },
      error: () => {},
    });
  }

  rejectSuggestion(org: string) {
    this.api.rejectTrustedCloudSuggestion(org).subscribe({
      next: () => { this.trustedCloud.suggestions = this.trustedCloud.suggestions.filter(s => s.org !== org); this.cdr.detectChanges(); },
      error: () => {},
    });
  }
}
