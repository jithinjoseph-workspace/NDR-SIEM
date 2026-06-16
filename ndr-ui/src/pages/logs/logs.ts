import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';
import { Websocket } from '../../services/websocket/websocket';
import { Subscription } from 'rxjs';
import { LucideAngularModule, Search, Terminal, RefreshCw } from 'lucide-angular';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-logs',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, FormsModule],
  templateUrl: './logs.html',
  styleUrl: './logs.css'
})
export class Logs implements OnInit, OnDestroy {
  logs: any[] = [];
  filteredLogs: any[] = [];
  searchText: string = '';
  totalCount: number = 0;
  loading: boolean = true;

  TerminalIcon = Terminal;
  SearchIcon = Search;
  RefreshIcon = RefreshCw;

  private subs: Subscription[] = [];

  private updateScheduled = false;
  private scheduleUpdate() {
    if (this.updateScheduled) return;
    this.updateScheduled = true;
    requestAnimationFrame(() => {
      this.cdr.detectChanges();
      this.updateScheduled = false;
    });
  }

  constructor(
    private api: Api,
    private ws: Websocket,
    private cdr: ChangeDetectorRef,
    private route: ActivatedRoute  // ← add this

  ) { }

  ngOnInit() {
    this.route.queryParams.subscribe(params => {
      if (params['search']) {
        this.searchText = params['search'];
        this.onSearch();
      }
    });

    this.loadLogs();

    // Real-time new events via WebSocket
    this.subs.push(
      this.ws.events$.subscribe((event: any) => {
        const evtTime = event.ts
          ? new Date(event.ts * 1000).toLocaleTimeString('en-US', {
              hour: '2-digit', minute: '2-digit', second: '2-digit'
            })
          : new Date().toLocaleTimeString('en-US', {
              hour: '2-digit', minute: '2-digit', second: '2-digit'
            });
        const log = {
          ts: evtTime,
          proto: event.proto?.toUpperCase() || '-',
          src: event.src || '-',
          dst: event.dst || '-',
          source: event.type || '-',
          action: 'ALLOW',
          event_type: event.event_type || '-',
        };
        this.logs.unshift(log);
        if (this.logs.length > 200) this.logs.pop();
        this.applyFilter();
        this.scheduleUpdate();
      })
    );
  }

  loadLogs() {
    this.loading = true;
    this.api.getRecentEvents().subscribe({
      next: (data: any[]) => {
        this.logs = data.map(e => ({
          ts: new Date(e.timestamp * 1000).toLocaleTimeString('en-US', {
            hour: '2-digit', minute: '2-digit', second: '2-digit'
          }),
          proto: e.proto?.toUpperCase() || '-',
          src: e.src_ip || '-',
          dst: e.dst_ip || '-',
          source: e.source || '-',
          action: 'ALLOW',
          event_type: e.event_type || '-',
        }));
        this.totalCount = data.length;
        this.applyFilter();
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  applyFilter() {
    if (!this.searchText) {
      this.filteredLogs = this.logs;
    } else {
      const s = this.searchText.toLowerCase();
      this.filteredLogs = this.logs.filter(l =>
        l.src?.toLowerCase().includes(s) ||
        l.dst?.toLowerCase().includes(s) ||
        l.proto?.toLowerCase().includes(s) ||
        l.source?.toLowerCase().includes(s)
      );
    }
  }

  onSearch() {
    this.applyFilter();
    this.cdr.detectChanges();
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
  }
}
