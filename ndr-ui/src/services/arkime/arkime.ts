import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class ArkimeService {
  constructor(private http: HttpClient) {}

  private headers(): HttpHeaders {
    return new HttpHeaders({
      Authorization: `Bearer ${localStorage.getItem('token')}`,
    });
  }

  getStatus(): Observable<any> {
    return this.http.get('/api/arkime/status', { headers: this.headers() });
  }

  getSessions(params?: { cid?: string; ip?: string; limit?: number }): Observable<any> {
    let query = `/api/arkime/sessions?limit=${params?.limit ?? 50}`;
    if (params?.cid) query += `&cid=${encodeURIComponent(params.cid)}`;
    if (params?.ip)  query += `&ip=${encodeURIComponent(params.ip)}`;
    return this.http.get(query, { headers: this.headers() });
  }

  getSessionLink(communityId: string): Observable<any> {
    return this.http.get(`/api/arkime/link/${encodeURIComponent(communityId)}`, {
      headers: this.headers(),
    });
  }

  // Unified download: tries stored file first (remote sensor), falls back to Arkime proxy (on-premise)
  downloadPcap(sessionId: string): void {
    const token = localStorage.getItem('token');
    window.open(`/api/pcap/${encodeURIComponent(sessionId)}?token=${token}`, '_blank');
  }
}
