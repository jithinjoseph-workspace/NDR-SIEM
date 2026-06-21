import { Component, OnInit, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { EvidenceService } from '../../services/evidence/evidence';

const SEV_ORDER: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

@Component({
  selector: 'app-evidence',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './evidence.html',
  styleUrl: './evidence.css'
})
export class EvidenceComponent implements OnInit {

  // ── Raw data signals ─────────────────────────────────────────────
  bundles       = signal<any[]>([]);
  selectedBundle = signal<any>(null);
  timeline      = signal<any>(null);
  annotations   = signal<any[]>([]);
  log           = signal<any[]>([]);
  loading       = signal(false);

  // ── Bundle detail signals ─────────────────────────────────────────
  bundleContents   = signal<any>(null);
  contentsLoading  = signal(false);
  contentsError    = signal('');
  verifyResult     = signal<any>(null);

  // ── UI state signals ──────────────────────────────────────────────
  activeTab            = signal('bundles');
  activeContentSection = signal('attack_summary');
  expandedCids         = signal<Set<string>>(new Set());

  // ── Form fields (plain — no reactive tracking needed) ────────────
  holdReason = '';
  newNote    = '';
  newTag     = '';

  // ── Computed: group bundles by community_id, highest sev first ────
  groupedBundles = computed(() => {
    const map = new Map<string, any[]>();
    for (const b of this.bundles()) {
      const cid = b.community_id || b.id;
      if (!map.has(cid)) map.set(cid, []);
      map.get(cid)!.push(b);
    }
    const groups = Array.from(map.entries()).map(([cid, alerts]) => {
      const sorted = [...alerts].sort((a, b) =>
        (SEV_ORDER[b.severity?.toUpperCase()] ?? 0) -
        (SEV_ORDER[a.severity?.toUpperCase()] ?? 0)
      );
      return { community_id: cid, primary: sorted[0], alerts: sorted };
    });
    groups.sort((a, b) =>
      (SEV_ORDER[b.primary.severity?.toUpperCase()] ?? 0) -
      (SEV_ORDER[a.primary.severity?.toUpperCase()] ?? 0)
    );
    return groups;
  });

  private pendingCid: string | null = null;

  constructor(
    private evidenceService: EvidenceService,
    private route: ActivatedRoute
  ) {}

  ngOnInit() {
    this.route.queryParams.subscribe(params => {
      const cid = params['cid'];
      if (cid) this.pendingCid = cid;
    });
    this.loadBundles();
  }

  loadBundles() {
    this.loading.set(true);
    this.evidenceService.listBundles().subscribe({
      next: (r: any) => {
        this.bundles.set(r.bundles || []);
        this.loading.set(false);
        const all = this.bundles();
        if (this.pendingCid) {
          const match = all.find(b => b.community_id === this.pendingCid);
          if (match) { this.pendingCid = null; this.selectBundle(match); }
        } else if (!this.selectedBundle() && this.groupedBundles().length > 0) {
          this.selectBundle(this.groupedBundles()[0].primary);
        }
      },
      error: () => this.loading.set(false)
    });
  }

  selectBundle(b: any) {
    this.selectedBundle.set(b);
    this.activeTab.set('investigation');
    this.activeContentSection.set('attack_summary');
    this.loadTimeline(b.community_id);
    this.loadLog(b.community_id);
    this.loadAnnotations(b.id);
    this.loadBundleContents(b.id);
  }

  loadBundleContents(bundleId: string) {
    this.contentsLoading.set(true);
    this.contentsError.set('');
    this.bundleContents.set(null);
    this.evidenceService.getBundleContents(bundleId).subscribe({
      next:  (data: any) => { this.bundleContents.set(data);  this.contentsLoading.set(false); },
      error: ()          => { this.contentsError.set('Failed to load bundle contents'); this.contentsLoading.set(false); }
    });
  }

  toggleGroup(group: any, event: Event) {
    event.stopPropagation();
    this.expandedCids.update(s => {
      const next = new Set(s);
      if (next.has(group.community_id)) next.delete(group.community_id);
      else next.add(group.community_id);
      return next;
    });
  }

  connStateDesc(state: string): string {
    const descriptions: {[k: string]: string} = {
      'S0': 'Connection attempt, no reply', 'S1': 'Established, not terminated',
      'S2': 'Closed by originator', 'S3': 'Closed by responder',
      'SF': 'Normal close', 'REJ': 'Connection rejected',
      'RSTO': 'Reset by originator', 'RSTR': 'Reset by responder',
      'RSTOS0': 'Originator reset, no reply', 'RSTRH': 'Reset by responder, no SYN',
      'SH': 'SYN then half close', 'SHR': 'Responder SYN, half close',
      'OTH': 'No SYN, mid-stream'
    };
    return descriptions[state] || '';
  }

  loadTimeline(cid: string) {
    this.evidenceService.getTimeline(cid).subscribe((r: any) => this.timeline.set(r));
  }

  loadLog(cid: string) {
    this.evidenceService.getLog(cid).subscribe((r: any) => this.log.set(r.log || []));
  }

  loadAnnotations(bundleId: string) {
    this.evidenceService.getAnnotations(bundleId).subscribe((r: any) => this.annotations.set(r.annotations || []));
  }

  download(b: any) { this.evidenceService.downloadBundle(b.community_id); }

  verify(b: any) {
    this.activeTab.set('verify');
    this.verifyResult.set(null);
    this.evidenceService.verifyBundle(b.id).subscribe({
      next:  (r: any) => this.verifyResult.set(r),
      error: ()       => this.verifyResult.set({
        status: 'ERROR', stored_sha256: '-', computed_sha256: '-',
        verified_at: new Date().toISOString(), verified_by: '-'
      })
    });
  }

  setHold(b: any, hold: boolean) {
    const reason = hold ? this.holdReason : 'Hold cleared';
    this.evidenceService.setLegalHold(b.id, hold, reason).subscribe(() => {
      this.loadBundles(); this.holdReason = '';
    });
  }

  filterRules(rules: any[]): any[] {
    if (!rules) return [];
    return rules.filter(r => {
      const name = (r.name || '').trim();
      return name.includes(' ') || name.length >= 8;
    });
  }

  addNote(b: any) {
    if (!this.newNote) return;
    this.evidenceService.annotate(b.id, b.community_id, this.newNote, this.newTag)
      .subscribe(() => {
        this.loadAnnotations(b.id); this.newNote = ''; this.newTag = '';
      });
  }
}
