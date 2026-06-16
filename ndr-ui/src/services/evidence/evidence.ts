import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class EvidenceService {
  constructor(private http: HttpClient) {}

  private headers(): HttpHeaders {
    return new HttpHeaders({
      Authorization: `Bearer ${localStorage.getItem('ndr_token')}`
    });
  }

  // Download ZIP bundle — triggers browser download
  downloadBundle(communityId: string): void {
    const token = localStorage.getItem('ndr_token');
    const url = `/api/evidence/${encodeURIComponent(communityId)}?token=${token}`;
    const a = document.createElement('a');
    a.href = url;
    a.download = `evidence_${communityId}.zip`;
    a.click();
  }

  listBundles(limit = 50): Observable<any> {
    return this.http.get(`/api/evidence/bundles?limit=${limit}`,
      { headers: this.headers() });
  }

  getBundle(bundleId: string): Observable<any> {
    return this.http.get(`/api/evidence/bundle/${bundleId}`,
      { headers: this.headers() });
  }

  verifyBundle(bundleId: string): Observable<any> {
    return this.http.get(`/api/evidence/bundle/${bundleId}/verify`,
      { headers: this.headers() });
  }

  setLegalHold(bundleId: string, hold: boolean, reason: string): Observable<any> {
    return this.http.post(`/api/evidence/bundle/${bundleId}/hold`,
      { hold, reason }, { headers: this.headers() });
  }

  annotate(bundleId: string, communityId: string, note: string, tag: string): Observable<any> {
    return this.http.post(`/api/evidence/bundle/${bundleId}/annotate`,
      { community_id: communityId, note, tag }, { headers: this.headers() });
  }

  getAnnotations(bundleId: string): Observable<any> {
    return this.http.get(`/api/evidence/bundle/${bundleId}/annotations`,
      { headers: this.headers() });
  }

  getTimeline(communityId: string): Observable<any> {
    return this.http.get(`/api/evidence/${encodeURIComponent(communityId)}/timeline`,
      { headers: this.headers() });
  }

  getLog(communityId: string): Observable<any> {
    return this.http.get(`/api/evidence/${encodeURIComponent(communityId)}/log`,
      { headers: this.headers() });
  }

  checkIoc(value: string): Observable<any> {
    return this.http.get(`/api/evidence/iocs/check?value=${encodeURIComponent(value)}`,
      { headers: this.headers() });
  }
}
