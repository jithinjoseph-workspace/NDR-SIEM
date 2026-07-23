import { Injectable, NgZone } from '@angular/core';
import { Subject, BehaviorSubject, filter } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class Websocket {
  private socket: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private updateTimeout: any = null;

  public messages$ = new Subject<any>();
  public lastAgentStatus$ = new BehaviorSubject<any>(null);
  public lastInterfaces$ = new BehaviorSubject<any>(null);
  public lastTelemetry$ = new BehaviorSubject<any>(null);

  public agentStatus$ = this.messages$.pipe(filter(m => m.type === 'agent_status'));
  public interfaces$ = this.messages$.pipe(filter(m => m.type === 'interfaces'));
  public hits$ = this.messages$.pipe(filter(m => m.type === 'hit'));
  public telemetry$ = this.messages$.pipe(filter(m => m.type === 'telemetry'));
  public events$ = this.messages$.pipe(
    filter(m => m.type === 'agent-z' || m.type === 'agent-s')
  );

  private hitsHistory: any[] = [];
  public continuousHits$ = new BehaviorSubject<any[]>([]);

  constructor(private zone: NgZone) { 
    try {
      const stored = sessionStorage.getItem('ndr_live_hits');
      if (stored) {
        this.hitsHistory = JSON.parse(stored);
        this.continuousHits$.next(this.hitsHistory);
      }
    } catch (e) {
      console.warn('Failed to parse cached live hits', e);
    }
  }

  connect() {
    // ── Guard: do not open a second connection if one is already live ──────
    if (
      this.socket &&
      (this.socket.readyState === WebSocket.OPEN ||
       this.socket.readyState === WebSocket.CONNECTING)
    ) {
      return;
    }

    // ── Cancel any pending reconnect timer ────────────────────────────────
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    // ── Cleanly close the old socket so its onclose cannot fire ──────────
    if (this.socket) {
      const stale = this.socket;
      stale.onclose = null; // prevent the stale handler from scheduling a reconnect
      stale.onerror = null;
      stale.close();
      this.socket = null;
    }

    try {
      const token = localStorage.getItem('ndr_token') || '';
      if (!token) {
        console.warn('No token found, aborting WebSocket connection');
        return;
      }

      const wsProtocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${wsProtocol}//${location.host}/ws`;

      this.socket = new WebSocket(wsUrl);

      // Send token as first message so it never appears in nginx logs or browser history
      this.socket.onopen = () => this.zone.run(() => {
        this.socket?.send(JSON.stringify({ type: 'auth', token }));
      });

      this.socket.onmessage = (event) => {
        // Run inside Angular zone so UI updates instantly
        this.zone.run(() => {
          try {
            const data = JSON.parse(event.data);
            this.messages$.next(data);
            if (data.type === 'agent_status') this.lastAgentStatus$.next(data);
            if (data.type === 'interfaces')  this.lastInterfaces$.next(data);
            if (data.type === 'telemetry')   this.lastTelemetry$.next(data);
            if (data.type === 'force_logout') {
              this.disconnect();
              localStorage.removeItem('ndr_token');
              localStorage.removeItem('ndr_user');
              sessionStorage.clear();
              window.location.href = '/login';
              return;
            }
            if (data.type === 'hit') {
              this.hitsHistory.unshift(data);
              if (this.hitsHistory.length > 100) this.hitsHistory.pop();

              // Throttle updates to BehaviorSubject and sessionStorage to prevent browser freeze
              if (!this.updateTimeout) {
                this.updateTimeout = setTimeout(() => {
                  this.updateTimeout = null;
                  this.continuousHits$.next([...this.hitsHistory]);
                  try {
                    sessionStorage.setItem('ndr_live_hits', JSON.stringify(this.hitsHistory));
                  } catch (e) {}
                }, 250);
              }
            }
          } catch (e) {
            console.warn('Invalid WS message:', event.data);
          }
        });
      };

      this.socket.onerror = (e) => console.error('WebSocket Error:', e);

      this.socket.onclose = () => {
        console.warn('WebSocket closed, reconnecting in 3s...');
        this.socket = null; // clear reference so the guard lets us reconnect
        this.reconnectTimer = setTimeout(() => {
          this.reconnectTimer = null;
          this.connect();
        }, 3000);
      };
    } catch (e) {
      console.warn('WebSocket failed, retrying in 3s...');
      this.reconnectTimer = setTimeout(() => {
        this.reconnectTimer = null;
        this.connect();
      }, 3000);
    }
  }

  disconnect() {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.updateTimeout !== null) {
      clearTimeout(this.updateTimeout);
      this.updateTimeout = null;
    }
    if (this.socket) {
      this.socket.onclose = null;
      this.socket.onerror = null;
      this.socket.close();
      this.socket = null;
    }
  }

  send(data: any) {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify(data));
    }
  }
}
