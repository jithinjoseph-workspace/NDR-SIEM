import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { map, Observable } from 'rxjs';

export interface SensorAssignment {
  user_id: string;
  sensor_id: string;
}

export interface SensorKey {
  id: string;
  key_prefix: string;
  key?: string;
  tenant_id: string;
  name: string;
  hostname?: string;
  interface?: string;
  os?: string;
  'agent-z'?: string;
  'agent-s'?: string;
  vector?: string;
  arkime?: string;
  arkime_url?: string;
  active: boolean;
  created_at: string;
  last_seen: string;
}

export type SensorControlCommand = 'start' | 'stop' | 'restart';

export interface Announcement {
  id: string;
  title: string;
  message: string;
  type: 'info' | 'maintenance' | 'update' | 'critical';
  audience: 'all' | 'tenant_admins' | 'tenant';
  tenant_id?: string;
  starts_at?: string;
  ends_at?: string;
  start_at?: string;
  end_at?: string;
  active: boolean;
  read?: boolean;
  status?: string;
  target_roles?: string[];
  target_tenants?: string[];
  created_at: string;
  updated_at?: string;
}

export interface SupportMessage {
  id: string;
  tenant_id: string;
  sender_username: string;
  sender_role: string;
  subject: string;
  category: string;
  message: string;
  status: string;
  admin_reply: string;
  replied_by: string;
  forwarded: number;
  forwarded_by: string;
  deleted: number;
  created_at: string;
  updated_at: string;
  replied_at: string;
  forwarded_at: string;
}

interface AnnouncementListResponse {
  status?: string;
  announcements?: Announcement[];
  message?: string;
}

interface SensorKeyListResponse {
  status?: string;
  keys?: SensorKey[];
  message?: string;
}

interface SupportMessageListResponse {
  status?: string;
  messages?: SupportMessage[];
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

  getRecentEvents(hours?: number): Observable<any[]> {
    let url = `${this.baseUrl}/events`;
    if (hours) {
      url += `?hours=${hours}`;
    }
    return this.http.get<any[]>(url);
  }

  getTopIps(): Observable<any> {
    return this.http.get(`${this.baseUrl}/top-ips`);
  }

  getSeverity(): Observable<any> {
    return this.http.get(`${this.baseUrl}/severity`);
  }

  getNetworkMap(mode?: string, limit?: number): Observable<any> {
    let url = `${this.baseUrl}/network-map`;
    const params: string[] = [];
    if (mode) params.push(`mode=${encodeURIComponent(mode)}`);
    if (limit !== undefined) params.push(`limit=${limit}`);
    if (params.length) url += '?' + params.join('&');
    return this.http.get(url);
  }

  getNetworkMapNode(ip: string): Observable<any> {
    return this.http.get(`${this.baseUrl}/network-map/node/${encodeURIComponent(ip)}`);
  }

  searchNetworkMap(query: string): Observable<string[]> {
    return this.http.get<string[]>(`${this.baseUrl}/network-map/search?q=${encodeURIComponent(query)}`);
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
  syncCommunityRules(): Observable<any> {
    return this.http.post(`${this.baseUrl}/rules/sync-community`, {});
  }

  getRuleHitCounts(): Observable<{ [ruleName: string]: number }> {
    return this.http.get<{ [ruleName: string]: number }>(`${this.baseUrl}/rules/hit-counts`);
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

  exportNetworkLogs(format: string, hours: number = 24): void {
    const url = `${this.baseUrl}/export-logs?format=${format}&hours=${hours}`;

    this.http.get(url, { responseType: 'blob', observe: 'response' })
      .subscribe(response => {
        const blob = response.body;
        if (!blob) return;

        const contentDisposition = response.headers.get('content-disposition');
        const filename = contentDisposition?.match(/filename="(.+)"/)?.[1]
          ?? `ndr-logs.${format === 'pdf' ? 'html' : format}`;

        const objectUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = objectUrl;
        link.download = filename;
        link.click();
        URL.revokeObjectURL(objectUrl);
      });
  }

  getPlaybooks(): Observable<any> {
    return this.http.get(`${this.baseUrl}/soar/status`);
  }

  getSettings(): Observable<any> {
    return this.http.get(`${this.baseUrl}/settings`);
  }

  updateSettings(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/settings`, data);
  }

  getAiConfig(): Observable<any> {
    return this.http.get(`${this.baseUrl}/settings/ai`);
  }

  updateAiConfig(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/settings/ai`, data);
  }

  listAiProviders(): Observable<any> {
    return this.http.get(`${this.baseUrl}/settings/ai/providers`);
  }

  saveAiProvider(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/settings/ai/providers`, data);
  }

  deleteAiProvider(name: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/settings/ai/providers/${encodeURIComponent(name)}`);
  }

  testAiProvider(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/settings/ai/providers/test`, data);
  }

  getTrustedCloudSettings(): Observable<any> {
    return this.http.get(`${this.baseUrl}/settings/trusted-cloud`);
  }

  updateTrustedCloudSettings(data: {keywords?: string[], domains?: string[]}): Observable<any> {
    return this.http.put(`${this.baseUrl}/settings/trusted-cloud`, data);
  }

  approveTrustedCloudSuggestion(org: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/settings/trusted-cloud/suggestions/approve`, { org });
  }

  rejectTrustedCloudSuggestion(org: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/settings/trusted-cloud/suggestions/reject`, { org });
  }

  getAssets(): Observable<any[]> {
    return this.http.get<any[]>(`${this.baseUrl}/assets`);
  }

  getIpamSubnets(): Observable<any[]> {
    return this.http.get<any[]>(`${this.baseUrl}/ipam/subnets`);
  }

  updateAsset(ip: string, payload: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/assets/${ip}`, payload);
  }

  setAssetTrusted(ip: string, trusted: boolean): Observable<any> {
    return this.http.patch(`${this.baseUrl}/assets/${ip}/trusted`, { trusted });
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

  setTenantAiEnabled(id: string, enabled: boolean): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/tenants/${id}/ai-enabled`, { enabled });
  }

  getAnnouncements(): Observable<Announcement[]> {
    return this.http
      .get<AnnouncementListResponse>(`${this.baseUrl}/announcements`)
      .pipe(map(response => {
        if (response.status && response.status !== 'ok') {
          throw new Error(response.message || 'Failed to load announcements');
        }
        return response.announcements || [];
      }));
  }

  getActiveAnnouncements(): Observable<Announcement[]> {
    return this.http
      .get<AnnouncementListResponse>(`${this.baseUrl}/announcements/active`)
      .pipe(map(response => {
        if (response.status && response.status !== 'ok') {
          throw new Error(response.message || 'Failed to load active announcements');
        }
        return response.announcements || [];
      }));
  }

  createAnnouncement(data: Partial<Announcement>): Observable<any> {
    return this.http.post(`${this.baseUrl}/announcements`, data);
  }

  updateAnnouncement(id: string, data: Partial<Announcement>): Observable<any> {
    return this.http.put(`${this.baseUrl}/announcements/${id}`, data);
  }

  markAnnouncementRead(id: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/announcements/${id}/read`, {});
  }

  deleteAnnouncement(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/announcements/${id}`);
  }

  getEngines(): Observable<any> {
    return this.http.get(`${this.baseUrl}/admin/engines`);
  }

  getPlatformTelemetry(): Observable<any> {
    return this.http.get(`${this.baseUrl}/admin/telemetry`);
  }


  getKafkaStatus(): Observable<any> {
    return this.http.get(`${this.baseUrl}/monitor/kafka`);
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

  reactivateSensorKey(id: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/sensor-keys/${id}/reactivate`, {});
  }

  controlSensor(command: SensorControlCommand, tenantId: string, sensorId: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/sensor/control`, {
      command,
      tenant_id: tenantId,
      sensor_id: sensorId,
    });
  }

  getSupportMessages(): Observable<SupportMessage[]> {
    return this.http
      .get<SupportMessageListResponse>(`${this.baseUrl}/support/messages`)
      .pipe(map(response => {
        if (response.status && response.status !== 'ok') {
          throw new Error(response.message || 'Failed to load support messages');
        }
        return response.messages || [];
      }));
  }

  createSupportMessage(data: { subject: string; category: string; message: string }): Observable<any> {
    return this.http.post(`${this.baseUrl}/support/messages`, data);
  }

  reviewSupportMessage(id: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/support/messages/${id}/review`, {});
  }

  replySupportMessage(id: string, reply: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/support/messages/${id}/reply`, { reply });
  }

  forwardSupportMessage(id: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/support/messages/${id}/forward`, {});
  }

  deleteSupportMessage(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/support/messages/${id}`);
  }

  // --- Native SOAR ---
  getNativePlaybooks(): Observable<any> {
    return this.http.get(`${this.baseUrl}/soar/native/playbooks`);
  }
  createNativePlaybook(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/soar/native/playbooks`, data);
  }
  updateNativePlaybook(id: string, data: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/soar/native/playbooks/${id}`, data);
  }
  deleteNativePlaybook(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/soar/native/playbooks/${id}`);
  }
  getSoarCases(): Observable<any> {
    return this.http.get(`${this.baseUrl}/soar/cases`);
  }
  updateSoarCaseStatus(id: string, status: string): Observable<any> {
    return this.http.put(`${this.baseUrl}/soar/cases/${id}/status`, { status });
  }
  getSoarCaseComments(id: string): Observable<any> {
    return this.http.get(`${this.baseUrl}/soar/cases/${id}/comments`);
  }
  addSoarCaseComment(id: string, comment: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/soar/cases/${id}/comments`, { comment });
  }
  getSoarRuns(): Observable<any> {
    return this.http.get(`${this.baseUrl}/soar/runs`);
  }

  getEventsByCid(cid: string): Observable<any> {
    return this.http.get(`${this.baseUrl}/events/by-cid?cid=${encodeURIComponent(cid)}`);
  }

  getAiActivity(): Observable<any> {
    return this.http.get(`${this.baseUrl}/ai-activity`);
  }

  deactivateAiSuppression(id: string): Observable<any> {
    return this.http.patch(`${this.baseUrl}/ai-suppressions/${id}/deactivate`, {});
  }

  deleteAiSuppression(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/ai-suppressions/${id}`);
  }

  getProtocols(): Observable<any> {
    return this.http.get(`${this.baseUrl}/protocols`);
  }

  updateIntegration(id: string, data: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/soar/integrations/${id}`, data);
  }

  getThreatPredictions(): Observable<any> {
    return this.http.get(`${this.baseUrl}/threat/predictions`);
  }


  getThreatExposure(): Observable<any> {
    return this.http.get(`${this.baseUrl}/threat/exposure`);
  }

  // ── Sensor Assignments ────────────────────────────────────────────────────

  getSensorAssignments(): Observable<{ assignments: SensorAssignment[] }> {
    return this.http.get<{ assignments: SensorAssignment[] }>(`${this.baseUrl}/sensors/assignments`);
  }

  assignSensor(user_id: string, sensor_id: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/sensors/assign`, { user_id, sensor_id });
  }

  unassignSensor(user_id: string, sensor_id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/sensors/assign`, { body: { user_id, sensor_id } });
  }
}
