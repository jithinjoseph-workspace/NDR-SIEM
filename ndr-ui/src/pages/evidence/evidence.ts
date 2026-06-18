import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { EvidenceService } from '../../services/evidence/evidence';

@Component({
  selector: 'app-evidence',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './evidence.html',
  styleUrl: './evidence.css'
})
export class EvidenceComponent implements OnInit {
  bundles: any[] = [];
  selectedBundle: any = null;
  timeline: any = null;
  annotations: any[] = [];
  log: any[] = [];
  loading = false;
  verifyResult: any = null;
  holdReason = '';
  newNote = '';
  newTag = '';
  activeTab = 'bundles';

  bundleContents: any = null;
  contentsLoading = false;
  contentsError = '';
  activeContentSection = 'attack_summary';

  private pendingCid: string | null = null;

  constructor(
    private evidenceService: EvidenceService,
    private cdr: ChangeDetectorRef,
    private route: ActivatedRoute
  ) {}

  ngOnInit() {
    this.route.queryParams.subscribe(params => {
      const cid = params['cid'];
      if (cid) { this.pendingCid = cid; }
    });
    this.loadBundles();
  }

  loadBundles() {
    this.loading = true;
    this.evidenceService.listBundles().subscribe({
      next: (r: any) => {
        this.bundles = r.bundles || [];
        this.loading = false;
        if (this.pendingCid) {
          const match = this.bundles.find(b => b.community_id === this.pendingCid);
          if (match) { this.pendingCid = null; this.selectBundle(match); }
        } else if (!this.selectedBundle && this.bundles.length > 0) {
          this.selectBundle(this.bundles[0]);
        }
        this.cdr.detectChanges();
      },
      error: () => { this.loading = false; this.cdr.detectChanges(); }
    });
  }

  selectBundle(b: any) {
    this.selectedBundle = b;
    this.activeTab = 'investigation';
    this.activeContentSection = 'attack_summary';
    this.cdr.detectChanges();
    this.loadTimeline(b.community_id);
    this.loadLog(b.community_id);
    this.loadAnnotations(b.id);
    this.loadBundleContents(b.id);
  }

  loadBundleContents(bundleId: string) {
    this.contentsLoading = true;
    this.contentsError = '';
    this.bundleContents = null;
    this.evidenceService.getBundleContents(bundleId).subscribe({
      next: (data: any) => {
        this.bundleContents = data;
        this.contentsLoading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.contentsError = 'Failed to load bundle contents';
        this.contentsLoading = false;
        this.cdr.detectChanges();
      }
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
    this.evidenceService.getTimeline(cid).subscribe((r: any) => {
      this.timeline = r; this.cdr.detectChanges();
    });
  }

  loadLog(cid: string) {
    this.evidenceService.getLog(cid).subscribe((r: any) => {
      this.log = r.log || []; this.cdr.detectChanges();
    });
  }

  loadAnnotations(bundleId: string) {
    this.evidenceService.getAnnotations(bundleId).subscribe((r: any) => {
      this.annotations = r.annotations || []; this.cdr.detectChanges();
    });
  }

  download(b: any) { this.evidenceService.downloadBundle(b.community_id); }

  verify(b: any) {
    this.activeTab = 'verify';
    this.verifyResult = null;
    this.cdr.detectChanges();
    this.evidenceService.verifyBundle(b.id).subscribe({
      next: (r: any) => { this.verifyResult = r; this.cdr.detectChanges(); },
      error: () => {
        this.verifyResult = { status: 'ERROR', stored_sha256: '-', computed_sha256: '-',
          verified_at: new Date().toISOString(), verified_by: '-' };
        this.cdr.detectChanges();
      }
    });
  }

  setHold(b: any, hold: boolean) {
    const reason = hold ? this.holdReason : 'Hold cleared';
    this.evidenceService.setLegalHold(b.id, hold, reason).subscribe(() => {
      this.loadBundles(); this.holdReason = '';
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
