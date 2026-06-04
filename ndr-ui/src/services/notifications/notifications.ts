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
      // ── Notification eligibility gate ────────────────────────────────────
      // Surface a hit in the bell if EITHER condition is true:
      //   1. threat_intel = true  → confirmed malicious IOC match
      //   2. severity is CRITICAL or HIGH → high-risk correlation hit
      //      regardless of whether the IP is in the IOC database
      //
      // Previously only threat_intel hits were passed through, meaning every
      // CRITICAL/HIGH alert from a non-IOC IP was silently dropped and the
      // bell never rang even for live confirmed threats.
      const severity     = (hit.severity ?? '').toUpperCase() as string;
      const isThreatIntel = !!hit.threat_intel;
      const isHighRisk   = ['CRITICAL', 'HIGH'].includes(severity);

      if (!isThreatIntel && !isHighRisk) return;

      const srcIp = hit.src || hit.suricata?.src || hit.zeek?.src || '-';
      const dstIp = hit.dst || hit.suricata?.dst || hit.zeek?.dst || '-';

      // Composite key: deduplicate notifications per IP pair so repeated hits
      // on the same flow increment the hit counter rather than flooding the list.
      const id = `${srcIp}|${dstIp}`;

      const alerts        = [...this.alertsSubject.value];
      const existingIndex = alerts.findIndex(a => a.id === id);

      const incoming: ThreatNotification = {
        id,
        message: isThreatIntel
          ? 'MALICIOUS IP DETECTED IN NETWORK TRAFFIC'
          : `${severity} SEVERITY ALERT DETECTED`,
        time:     new Date().toLocaleTimeString(),
        src_ip:   srcIp,
        dst_ip:   dstIp,
        severity: hit.severity || 'HIGH',
        score:    hit.score    || 0,
        hits:     1,
        tags:     hit.tags     || [],
      };

      if (existingIndex >= 0) {
        // Existing flow: bubble to top, merge tags, keep highest score.
        const existing = alerts[existingIndex];
        alerts.splice(existingIndex, 1);
        this.alertsSubject.next([{
          ...existing,
          time:     incoming.time,
          severity: incoming.severity,
          score:    Math.max(existing.score, incoming.score),
          hits:     existing.hits + 1,
          tags:     Array.from(new Set([...existing.tags, ...incoming.tags])),
        }, ...alerts].slice(0, 50));
      } else {
        // New flow: prepend and cap the list at 50 entries.
        this.alertsSubject.next([incoming, ...alerts].slice(0, 50));
      }

      // Unread badge: count distinct IP pairs seen since last panel open.
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
