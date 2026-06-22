import { Component, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { toSignal } from '@angular/core/rxjs-interop';
import { interval, of } from 'rxjs';
import { catchError, map, startWith, switchMap } from 'rxjs/operators';
import { Api } from '../../services/api/api';
import {
  LucideAngularModule,
  Bot, ShieldOff, FileText, ChevronDown, ChevronUp
} from 'lucide-angular';

@Component({
  selector: 'app-ai-activity',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './ai-activity.html',
  styleUrl: './ai-activity.css',
})
export class AiActivity {
  private api = inject(Api);

  BotIcon         = Bot;
  ShieldOffIcon   = ShieldOff;
  FileIcon        = FileText;
  ChevronDownIcon = ChevronDown;
  ChevronUpIcon   = ChevronUp;

  activeTab: 'analyses' | 'suppressions' = 'analyses';
  expandedAnalyses = new Set<string>();

  // Poll every 15 s, fires immediately on load.
  // catchError inside switchMap keeps the interval alive even on HTTP errors.
  // toSignal converts to a signal — Angular re-renders automatically when data arrives.
  private data = toSignal(
    interval(15_000).pipe(
      startWith(0),
      switchMap(() =>
        this.api.getAiActivity().pipe(
          map((d: any) => ({ analyses: d.analyses || [], suppressions: d.suppressions || [], error: '' })),
          catchError(() => of({ analyses: [], suppressions: [], error: 'Failed to load AI activity.' }))
        )
      )
    ),
    { initialValue: { analyses: [], suppressions: [], error: '' } }
  );

  analyses     = computed(() => this.data()?.analyses    ?? []);
  suppressions = computed(() => this.data()?.suppressions ?? []);
  error        = computed(() => this.data()?.error       ?? '');
  loading      = computed(() => this.data() === null);

  toggleAnalysis(id: string) {
    if (this.expandedAnalyses.has(id)) this.expandedAnalyses.delete(id);
    else this.expandedAnalyses.add(id);
  }

  isExpanded(id: string) { return this.expandedAnalyses.has(id); }

  sevClass(s: string) { return 'sev-' + (s || 'info').toLowerCase(); }

  suppressTypeLabel(t: string) {
    const map: Record<string, string> = {
      by_dst: 'By Destination IP',
      by_src: 'By Source IP',
      by_sid: 'By Signature ID',
    };
    return map[t] || t;
  }

  formatTime(ts: string) {
    if (!ts) return '';
    const d = new Date(ts.includes('T') ? ts : ts.replace(' ', 'T') + 'Z');
    return isNaN(d.getTime()) ? ts : d.toLocaleString();
  }
}
