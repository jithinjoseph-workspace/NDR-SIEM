import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
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
  activeTab = 'bundles'; // bundles | timeline | log | verify

  constructor(private evidenceService: EvidenceService) {}

  ngOnInit() { this.loadBundles(); }

  loadBundles() {
    this.loading = true;
    this.evidenceService.listBundles().subscribe({
      next: (r: any) => {
        this.bundles = r.bundles || [];
        this.loading = false;
      },
      error: () => { this.loading = false; }
    });
  }

  selectBundle(b: any) {
    this.selectedBundle = b;
    this.activeTab = 'bundles';
    this.loadTimeline(b.community_id);
    this.loadLog(b.community_id);
    this.loadAnnotations(b.id);
  }

  loadTimeline(cid: string) {
    this.evidenceService.getTimeline(cid).subscribe((r: any) => {
      this.timeline = r;
    });
  }

  loadLog(cid: string) {
    this.evidenceService.getLog(cid).subscribe((r: any) => {
      this.log = r.log || [];
    });
  }

  loadAnnotations(bundleId: string) {
    this.evidenceService.getAnnotations(bundleId).subscribe((r: any) => {
      this.annotations = r.annotations || [];
    });
  }

  download(b: any) {
    this.evidenceService.downloadBundle(b.community_id);
  }

  verify(b: any) {
    this.activeTab = 'verify';
    this.verifyResult = null;
    this.evidenceService.verifyBundle(b.id).subscribe((r: any) => {
      this.verifyResult = r;
    });
  }

  setHold(b: any, hold: boolean) {
    const reason = hold ? this.holdReason : 'Hold cleared';
    this.evidenceService.setLegalHold(b.id, hold, reason).subscribe(() => {
      this.loadBundles();
      this.holdReason = '';
    });
  }

  addNote(b: any) {
    if (!this.newNote) return;
    this.evidenceService.annotate(b.id, b.community_id, this.newNote, this.newTag)
      .subscribe(() => {
        this.loadAnnotations(b.id);
        this.newNote = '';
        this.newTag = '';
      });
  }
}
