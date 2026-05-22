import { Injectable, OnDestroy } from '@angular/core';
import { Api } from '../api/api';
import { Subscription } from 'rxjs';

export interface ChartSnapshot {
  labels: string[];
  data: number[];
}

const STORAGE_KEY = 'ndr_chart_data';

@Injectable({
  providedIn: 'root'
})
export class ChartDataService implements OnDestroy {
  private labels: string[] = [];
  private data: number[] = [];
  private maxPoints = 20;
  private refreshInterval: any = null;
  private statsSub: Subscription | null = null;
  private started = false;
  private latestEventsLastHour = 0;

  constructor(private api: Api) {
    this.loadFromStorage();
  }

  /** Start accumulating chart data (idempotent — only starts once). */
  start(): void {
    if (this.started) return;
    this.started = true;

    // Fetch initial data point immediately
    this.fetchAndPush();

    // Keep fetching every 30 seconds, even when dashboard is not visible
    this.refreshInterval = setInterval(() => {
      this.fetchAndPush();
    }, 30000);
  }

  /** Get the current chart snapshot. */
  getSnapshot(): ChartSnapshot {
    // If no data has been collected yet, return a placeholder
    if (this.labels.length === 0) {
      return { labels: [''], data: [0] };
    }
    return {
      labels: [...this.labels],
      data: [...this.data]
    };
  }

  /** Returns the latest events-last-hour value. */
  getLatestEventsLastHour(): number {
    return this.latestEventsLastHour;
  }

  private fetchAndPush(): void {
    this.statsSub?.unsubscribe();
    this.statsSub = this.api.getStats().subscribe(stats => {
      this.latestEventsLastHour = stats.events_1h || 0;
      this.pushPoint(this.latestEventsLastHour);
    });
  }

  private pushPoint(value: number): void {
    const now = new Date().toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit'
    });

    if (this.labels.length >= this.maxPoints) {
      this.labels.shift();
      this.data.shift();
    }

    this.labels.push(now);
    this.data.push(value);
    this.saveToStorage();
  }

  /** Persist chart data to localStorage */
  private saveToStorage(): void {
    try {
      const payload = JSON.stringify({
        labels: this.labels,
        data: this.data,
        timestamp: Date.now()
      });
      localStorage.setItem(STORAGE_KEY, payload);
    } catch (_) {
      // localStorage might be full or unavailable — silently ignore
    }
  }

  /** Restore chart data from localStorage (discard if older than 10 minutes) */
  private loadFromStorage(): void {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;

      const stored = JSON.parse(raw);
      const ageMs = Date.now() - (stored.timestamp || 0);

      // Discard stale data older than 20 minutes
      if (ageMs > 20 * 60 * 1000) {
        localStorage.removeItem(STORAGE_KEY);
        return;
      }

      if (Array.isArray(stored.labels) && Array.isArray(stored.data)) {
        this.labels = stored.labels;
        this.data = stored.data;
      }
    } catch (_) {
      // Corrupted data — ignore and start fresh
    }
  }

  ngOnDestroy(): void {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
    this.statsSub?.unsubscribe();
  }
}
