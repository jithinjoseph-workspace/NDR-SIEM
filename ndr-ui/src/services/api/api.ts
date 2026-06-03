import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { map, Observable } from 'rxjs';

export interface SensorKey {
  id: string;
  key_prefix: string;
  key?: string;
  tenant_id: string;
  name: string;
  hostname?: string;
  interface?: string;
  os?: string;
  zeek?: string;
  suricata?: string;
  vector?: string;
  active: boolean;
  created_at: string;
  last_seen: string;
}

export type SensorControlCommand = 'start' | 'stop' | 'restart';

interface SensorKeyListResponse {
  status?: string;
  keys?: SensorKey[];
  message?: string;
}

@Injectable({
  providedIn: 'root'
})
export class Api {
  // Relative base so requests route correctly in every environment:
  // - Dev: Angular CLI proxy forwards /api → localhost:3000
  // - Production: nginx proxies /api → ndr_engines upstream
  // Never use an absolute URL here — it breaks remote browser access.
  private readonly baseUrl = '/api';

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
    const url = `${this.baseUrl}/export?format=${format}&hours=${hours}`;

    this.http.get(url, { responseType: 'blob', observe: 'response' })
      .subscribe(response => {
        const blob = response.body;
        if (!blob) return;

        const contentDisposition = response.headers.get('content-disposition');
        const filename = contentDisposition?.match(/filename="(.+)"/)?.[1]
          ?? `ndr-report.${format === 'pdf' ? 'html' : format}`;

        const objectUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = objectUrl;
        link.download = filename;
        link.click();
        URL.revokeObjectURL(objectUrl);
      });
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

  getSoarExecutions(): Observable<any> {
    return this.http.get(`${this.baseUrl}/soar/executions`);
  }

  configureSoarSlack(data: any): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/soar/action/slack`, data);
  }

  configureSoarEmail(data: any): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/soar/action/email`, data);
  }

  togglePlaybook(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/soar/playbook/toggle`, data);
  }
  createPlaybook(data: any): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/soar/playbook/create`, data);
  }

  getIntegrations(): Observable<any> {
    return this.http.get(
      `${this.baseUrl}/soar/integrations`);
  }

  saveIntegration(data: any): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/soar/integrations`, data);
  }

  testIntegration(data: any): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/soar/integrations/test`, data);
  }

  toggleIntegration(data: any): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/soar/integrations/toggle`, data);
  }

  deleteIntegration(data: any): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/soar/integrations/delete`, data);
  }

  getJiraTickets(config: any): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/soar/jira/tickets`, config);
  }
  // User management
  getUsers(): Observable<any> {
    return this.http.get(`${this.baseUrl}/auth/users`);
  }

  createUser(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/users`, data);
  }

  updateUser(id: string, data: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/auth/users/${id}`, data);
  }

  setUserStatus(id: string, active: boolean): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/users/${id}/status`, { active });
  }

  updateUserPermissions(id: string, permissions: string[]): Observable<any> {
    return this.http.put(`${this.baseUrl}/auth/users/${id}/permissions`, { permissions });
  }

  resetUserPassword(id: string, password: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/users/${id}/password`, { password });
  }

  deleteUser(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/auth/users/${id}`);
  }

  // Tenant management
  getTenants(): Observable<any> {
    return this.http.get(`${this.baseUrl}/auth/tenants`);
  }

  createTenant(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/tenants`, data);
  }

  updateTenant(id: string, data: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/auth/tenants/${id}`, data);
  }

  setTenantStatus(id: string, active: boolean): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/tenants/${id}/status`, { active });
  }

  getEngines(): Observable<any> {
    return this.http.get(`${this.baseUrl}/admin/engines`);
  }

  scaleEngines(action: string, engine?: string): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/admin/engines/scale`,
      { action, engine }
    );
  }

  getSensorKeys(): Observable<SensorKey[]> {
    return this.http
      .get<SensorKeyListResponse | SensorKey[]>(`${this.baseUrl}/sensor-keys`)
      .pipe(map(response => {
        if (Array.isArray(response)) {
          return response;
        }
        if (response.status && response.status !== 'ok') {
          throw new Error(response.message || 'Failed to load sensor keys');
        }
        return response.keys || [];
      }));
  }

  createSensorKey(tenantId: string, name: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/sensor-keys`, {
      tenant_id: tenantId,
      name,
    });
  }

  revokeSensorKey(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/sensor-keys/${id}`);
  }

  controlSensor(command: SensorControlCommand, tenantId: string, sensorId: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/sensor/control`, {
      command,
      tenant_id: tenantId,
      sensor_id: sensorId,
    });
  }
}
