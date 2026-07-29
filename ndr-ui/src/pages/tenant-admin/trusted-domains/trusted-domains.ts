import { Component, Input, OnInit, ChangeDetectionStrategy, signal, computed, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  ShieldCheck, Globe, Plus, Activity, Sparkles, Bot,
} from 'lucide-angular';
import { Api } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';

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
  @Input() tenantId = '';

  ShieldIcon    = ShieldCheck;
  GlobeIcon     = Globe;
  PlusIcon      = Plus;
  ActivityIcon  = Activity;
  SparklesIcon  = Sparkles;
  BotIcon       = Bot;

  readonly trustedDomains        = signal<any[]>([]);
  readonly loadingTrustedDomains = signal(false);
  readonly tdNewDomain           = signal('');
  readonly tdNewCategory         = signal('dns_beacon');
  readonly tdNewNote             = signal('');
  readonly tdSaving              = signal(false);
  readonly tdAiLoading           = signal(false);
  readonly tdAiAvailable         = signal<boolean | null>(null);
  readonly tdAiSuggestions       = signal<any[]>([]);

  readonly tenantOwnDomains = computed(() => this.trustedDomains().filter(d => d.scope === 'tenant'));
  readonly globalDomains    = computed(() => this.trustedDomains().filter(d => d.scope === 'global'));

  trackByIndex(i: number) { return i; }

  constructor(private api: Api, private auth: AuthService) {}

  ngOnInit() {
    if (!this.tenantId) {
      this.tenantId = this.auth.getUser()?.tenant_id || 'default';
    }
    this.loadTrustedDomains();
  }

  loadTrustedDomains() {
    this.loadingTrustedDomains.set(true);
    this.api.listTrustedDomains().subscribe({
      next: (data: any) => {
        this.trustedDomains.set(data.domains || []);
        this.loadingTrustedDomains.set(false);
      },
      error: () => { this.loadingTrustedDomains.set(false); },
    });
  }

  addTrustedDomain() {
    const d = this.tdNewDomain().trim().toLowerCase();
    if (!d) return;
    this.tdSaving.set(true);
    this.api.addTrustedDomain(d, this.tdNewCategory(), 'own', this.tdNewNote()).subscribe({
      next: () => {
        this.tdNewDomain.set('');
        this.tdNewNote.set('');
        this.tdSaving.set(false);
        this.loadTrustedDomains();
      },
      error: () => { this.tdSaving.set(false); },
    });
  }

  deleteTenantTrustedDomain(domain: string, tenantId: string) {
    this.api.deleteTrustedDomain(domain, tenantId).subscribe({
      next: () => {
        this.trustedDomains.update(list =>
          list.filter(d => !(d.domain === domain && d.tenant_id === tenantId))
        );
      },
      error: () => {},
    });
  }

  runAiSuggest() {
    this.tdAiLoading.set(true);
    this.tdAiSuggestions.set([]);
    this.api.aiSuggestTrustedDomains().subscribe({
      next: (data: any) => {
        this.tdAiAvailable.set(data.ai_available !== false);
        this.tdAiSuggestions.set((data.suggestions || []).filter((s: any) => s.verdict === 'TRUSTED'));
        this.tdAiLoading.set(false);
      },
      error: () => { this.tdAiLoading.set(false); },
    });
  }

  approveTdSuggestion(s: any) {
    this.api.addTrustedDomain(s.domain, 'dns_beacon', 'own', s.reason || '').subscribe({
      next: () => {
        this.tdAiSuggestions.update(list => list.filter(x => x.domain !== s.domain));
        this.loadTrustedDomains();
      },
      error: () => {},
    });
  }

  dismissTdSuggestion(domain: string) {
    this.tdAiSuggestions.update(list => list.filter(s => s.domain !== domain));
  }
}
