import { Component, OnInit, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Globe, Plus, RefreshCw, ShieldCheck, Trash2,
} from 'lucide-angular';
import { Api } from '../../../services/api/api';

@Component({
  selector: 'app-trusted-domains',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './trusted-domains.html',
  styleUrl: './trusted-domains.css',
})
export class TrustedDomains implements OnInit {
  GlobeIcon   = Globe;
  PlusIcon    = Plus;
  RefreshIcon = RefreshCw;
  ShieldIcon  = ShieldCheck;
  TrashIcon   = Trash2;

  tenants: any[]         = [];
  trustedDomains: any[]  = [];
  loadingTrustedDomains  = false;
  tdNewDomain            = '';
  tdNewCategory          = 'dns_beacon';
  tdNewScope             = '';   // '' = global, or a tenant_id
  tdNewNote              = '';
  tdSaving               = false;
  tdAiLoading            = false;
  tdAiAvailable: boolean | null = null;
  tdAiSuggestions: any[] = [];

  constructor(private api: Api, private cdr: ChangeDetectorRef) {}

  ngOnInit() {
    this.loadTrustedDomains();
    this.api.getTenants().subscribe({
      next: (data: any) => { this.tenants = data.tenants || []; this.cdr.detectChanges(); },
      error: () => {},
    });
  }

  loadTrustedDomains() {
    this.loadingTrustedDomains = true;
    this.api.listTrustedDomains().subscribe({
      next: (data: any) => { this.trustedDomains = data.domains || []; this.loadingTrustedDomains = false; this.cdr.detectChanges(); },
      error: () => { this.loadingTrustedDomains = false; this.cdr.detectChanges(); },
    });
  }

  addTrustedDomain() {
    const d = this.tdNewDomain.trim().toLowerCase();
    if (!d) return;
    this.tdSaving = true;
    this.api.addTrustedDomain(d, this.tdNewCategory, this.tdNewScope, this.tdNewNote).subscribe({
      next: () => { this.tdNewDomain = ''; this.tdNewNote = ''; this.tdSaving = false; this.loadTrustedDomains(); this.cdr.detectChanges(); },
      error: () => { this.tdSaving = false; this.cdr.detectChanges(); },
    });
  }

  deleteTrustedDomain(domain: string, tenantId: string) {
    this.api.deleteTrustedDomain(domain, tenantId).subscribe({
      next: () => {
        this.trustedDomains = this.trustedDomains.filter(d => !(d.domain === domain && d.tenant_id === tenantId));
        this.cdr.detectChanges();
      },
      error: () => {},
    });
  }

  runAiSuggest() {
    this.tdAiLoading = true; this.tdAiSuggestions = [];
    this.api.aiSuggestTrustedDomains().subscribe({
      next: (data: any) => {
        this.tdAiAvailable   = data.ai_available !== false;
        this.tdAiSuggestions = data.suggestions || [];
        this.tdAiLoading     = false;
        this.cdr.detectChanges();
      },
      error: () => { this.tdAiLoading = false; this.cdr.detectChanges(); },
    });
  }

  approveTdSuggestion(s: any) {
    this.api.addTrustedDomain(s.domain, 'dns_beacon', '', s.reason || '').subscribe({
      next: () => { this.tdAiSuggestions = this.tdAiSuggestions.filter(x => x.domain !== s.domain); this.loadTrustedDomains(); this.cdr.detectChanges(); },
      error: () => {},
    });
  }

  dismissTdSuggestion(domain: string) { this.tdAiSuggestions = this.tdAiSuggestions.filter(s => s.domain !== domain); this.cdr.detectChanges(); }

  get globalDomains() { return this.trustedDomains.filter(d => d.scope === 'global'); }
  get tenantDomains() { return this.trustedDomains.filter(d => d.scope === 'tenant'); }
}
