import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class Api {
  private baseUrl = 'http://localhost:3000/api';

  constructor(private http: HttpClient) { }

  getDashboardStats(): Observable<any> {
    return this.http.get(`${this.baseUrl}/health`);
  }

  getAlerts(): Observable<any[]> {
    return this.http.get<any[]>(`${this.baseUrl}/hits`); // assuming hits endpoint exists or we'll add it
  }

  getInterfaces(): Observable<string[]> {
    return this.http.get<string[]>(`${this.baseUrl}/interfaces`);
  }

  getAgentStatus(): Observable<any> {
    return this.http.get(`${this.baseUrl}/agent-status`);
  }

  getInterface(): Observable<any> {
    return this.http.get(`${this.baseUrl}/interface`);
  }

  setInterface(iface: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/interface`, { interface: iface });
  }

  startServices(): Observable<any> {
    return this.http.post(`${this.baseUrl}/start`, {});
  }

  stopServices(): Observable<any> {
    return this.http.post(`${this.baseUrl}/stop`, {});
  }

  getStats(): Observable<any> {
    return this.http.get(`${this.baseUrl}/stats`);
  }

  getRecentEvents(): Observable<any[]> {
    return this.http.get<any[]>(`${this.baseUrl}/events`);
  }

  getTopIps(): Observable<any> {
    return this.http.get(`${this.baseUrl}/top-ips`);
  }

  getSeverity(): Observable<any> {
    return this.http.get(`${this.baseUrl}/severity`);
  }

  getNetworkMap(): Observable<any> {
    return this.http.get(`${this.baseUrl}/network-map`);
  }

  getScaleStatus(): Observable<any> {
    return this.http.get(`${this.baseUrl}/scale-status`);
  }
  getRules(): Observable<any[]> {
    return this.http.get<any[]>(`${this.baseUrl}/rules`);
  }



  createRule(rule: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/rules`, rule);
  }

  deleteRule(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/rules/${id}`);
  }



  getThreatIntel(): Observable<any> {
    return this.http.get(`${this.baseUrl}/threat-intel`);
  }

  lookupIoc(ip: string): Observable<any> {
    return this.http.get(`${this.baseUrl}/threat-intel/${ip}`);
  }
  reloadRules(): Observable<any> {
    return this.http.post(`${this.baseUrl}/rules/reload`, {});
  }

  getRuleById(id: string): Observable<any> {
    return this.http.get(`${this.baseUrl}/rules/${id}`);
  }

  toggleRule(id: string, enabled: boolean): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/rules/${id}/toggle`,
      { enabled }
    );
  }

  exportReport(format: string, hours: number = 24): void {
    const url = `http://localhost:3000/api/export?format=${format}&hours=${hours}`;
    window.open(url, '_blank');
  }

  getSoarStatus(): Observable<any> {
    return this.http.get(`${this.baseUrl}/soar/status`);
  }

  setupSoar(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/soar/setup`, data);
  }

  updateSoarConfig(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/soar/config`, data);
  }

  testSoarWebhook(): Observable<any> {
    return this.http.post(`${this.baseUrl}/soar/test`, {});
  }


  getSettings(): Observable<any> {
    return this.http.get(`${this.baseUrl}/settings`);
}

updateSettings(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/settings`, data);
}

}

