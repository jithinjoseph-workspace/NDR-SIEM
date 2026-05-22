import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import { Websocket } from '../websocket/websocket';

export interface ThreatNotification {
  id: string;
  message: string;
  time: string;
  src_ip: string;
  dst_ip: string;
  severity: string;
  score: number;
  hits: number;
  tags: string[];
}

@Injectable({
  providedIn: 'root',
})
export class Notifications {
  private readonly alertsSubject = new BehaviorSubject<ThreatNotification[]>([]);
  private readonly unreadCountSubject = new BehaviorSubject<number>(0);
  private readonly unreadNotificationIds = new Set<string>();

  readonly alerts$ = this.alertsSubject.asObservable();
  readonly unreadCount$ = this.unreadCountSubject.asObservable();

  constructor(private ws: Websocket) {
    this.ws.hits$.subscribe((hit: any) => {
      if (!hit.threat_intel) return;

      const srcIp = hit.src || hit.suricata?.src || hit.zeek?.src || '-';
      const dstIp = hit.dst || hit.suricata?.dst || hit.zeek?.dst || '-';
      const id = `${srcIp}|${dstIp}`;
      const alerts = [...this.alertsSubject.value];
      const existingIndex = alerts.findIndex(alert => alert.id === id);

      const alert: ThreatNotification = {
        id,
        message: 'MALICIOUS IP DETECTED IN NETWORK TRAFFIC',
        time: new Date().toLocaleTimeString(),
        src_ip: srcIp,
        dst_ip: dstIp,
        severity: hit.severity || 'HIGH',
        score: hit.score || 0,
        hits: 1,
        tags: hit.tags || [],
      };

      if (existingIndex >= 0) {
        const existing = alerts[existingIndex];
        alerts.splice(existingIndex, 1);
        this.alertsSubject.next([{
          ...existing,
          time: alert.time,
          severity: alert.severity,
          score: Math.max(existing.score, alert.score),
          hits: existing.hits + 1,
          tags: Array.from(new Set([...existing.tags, ...alert.tags])),
        }, ...alerts].slice(0, 50));
      } else {
        this.alertsSubject.next([alert, ...alerts].slice(0, 50));
      }

      this.unreadNotificationIds.add(id);
      this.unreadCountSubject.next(this.unreadNotificationIds.size);
    });
  }

  markAllRead() {
    this.unreadNotificationIds.clear();
    this.unreadCountSubject.next(0);
  }

  clearAlerts() {
    this.alertsSubject.next([]);
    this.markAllRead();
  }
}
