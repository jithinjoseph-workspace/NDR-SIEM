import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class ArkimeService {
  constructor(private http: HttpClient) {}

  getStatus(): Observable<any> {
    return this.http.get('/api/arkime/status');
  }

  getSessions(params?: { cid?: string; ip?: string; src_ip?: string; dst_ip?: string; limit?: number }): Observable<any> {
    let query = `/api/arkime/sessions?limit=${params?.limit ?? 50}`;
    if (params?.cid)    query += `&cid=${encodeURIComponent(params.cid)}`;
    if (params?.ip)     query += `&ip=${encodeURIComponent(params.ip)}`;
    if (params?.src_ip) query += `&src_ip=${encodeURIComponent(params.src_ip)}`;
    if (params?.dst_ip) query += `&dst_ip=${encodeURIComponent(params.dst_ip)}`;
    return this.http.get(query);
  }

  getSessionLink(communityId: string): Observable<any> {
    return this.http.get(`/api/arkime/link/${encodeURIComponent(communityId)}`);
  }

  // Cookie is sent automatically with same-origin navigation — no token param needed.
  downloadPcap(sessionId: string): void {
    window.open(`/api/pcap/${encodeURIComponent(sessionId)}`, '_blank');
  }
}
