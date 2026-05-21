import { Injectable, NgZone } from '@angular/core';
import { Subject, BehaviorSubject, filter } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class Websocket {
  private socket: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  public messages$ = new Subject<any>();
  public lastAgentStatus$ = new BehaviorSubject<any>(null);
  public lastInterfaces$ = new BehaviorSubject<any>(null);

  public agentStatus$ = this.messages$.pipe(filter(m => m.type === 'agent_status'));
  public interfaces$ = this.messages$.pipe(filter(m => m.type === 'interfaces'));
  public hits$ = this.messages$.pipe(filter(m => m.type === 'hit'));
  public events$ = this.messages$.pipe(
    filter(m => m.type === 'zeek' || m.type === 'suricata')
  );

  constructor(private zone: NgZone) { }

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

    console.log('Connecting to websocket...');
    try {
      const token = localStorage.getItem('ndr_token') || '';
      const wsUrl = token
        ? `ws://localhost:3000/ws?token=${token}`
        : 'ws://localhost:3000/ws';

      this.socket = new WebSocket(wsUrl);

      this.socket.onmessage = (event) => {
        // Run inside Angular zone so UI updates instantly
        this.zone.run(() => {
          try {
            const data = JSON.parse(event.data);
            this.messages$.next(data);
            console.log(data);
            if (data.type === 'agent_status') this.lastAgentStatus$.next(data);
            if (data.type === 'interfaces') this.lastInterfaces$.next(data);
          } catch (e) {
            console.warn('Invalid WS message:', event.data);
          }
        });
      };

      this.socket.onopen = () =>
        this.zone.run(() => console.log('WebSocket Connected'));

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
