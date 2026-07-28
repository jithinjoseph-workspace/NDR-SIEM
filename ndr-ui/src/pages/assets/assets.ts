import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';
import {
  LucideAngularModule,
  Server,
  Monitor,
  Smartphone,
  Printer,
  Router,
  Lightbulb,
  Search,
  Filter,
  Check,
  X,
  Edit,
  ChevronDown,
  ShieldCheck,
  ShieldOff,
  AlertTriangle
} from 'lucide-angular';

import { DeviceDrawer } from '../../components/device-drawer/device-drawer';
import { AuthService } from '../../services/auth/auth';


@Component({
  selector: 'app-assets',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule, DeviceDrawer],
  templateUrl: './assets.html',
  styleUrl: './assets.css',
})
export class Assets implements OnInit {
  ServerIcon = Server;
  MonitorIcon = Monitor;
  SmartphoneIcon = Smartphone;
  PrinterIcon = Printer;
  RouterIcon = Router;
  LightbulbIcon = Lightbulb;
  SearchIcon = Search;
  FilterIcon = Filter;
  CheckIcon = Check;
  XIcon = X;
  ShieldCheckIcon = ShieldCheck;
  ShieldOffIcon = ShieldOff;
  AlertTriangleIcon = AlertTriangle;
  EditIcon = Edit;
  ChevronDownIcon = ChevronDown;

  assets: any[] = [];
  filteredAssets: any[] = [];
  loading = true;
  searchTerm = '';
  filterDeviceType = 'all';
  filterSubnet = 'all';
  filterLast24h = false;
  editingIp: string | null = null;
  editNameValue = '';

  subnets: any[] = [];
  isSubnetDropdownOpen = false;

  selectedAsset: any = null;

  isDropdownOpen = false;
  
  deviceTypeOptions = [
    { value: 'all', label: 'All Devices' },
    { value: 'laptop', label: 'Laptop' },
    { value: 'desktop', label: 'Desktop' },
    { value: 'phone', label: 'Phone / Mobile' },
    { value: 'tablet', label: 'Tablet' },
    { value: 'iot', label: 'IoT' },
    { value: 'printer', label: 'Printer' },
    { value: 'tv', label: 'TV / Media' },
    { value: 'server', label: 'Server' },
    { value: 'router', label: 'Router / Gateway' },
    { value: 'unknown', label: 'Unknown' }
  ];

  getFilterLabel(): string {
    const option = this.deviceTypeOptions.find(o => o.value === this.filterDeviceType);
    return option ? option.label : 'All Devices';
  }

  setFilter(value: string) {
    this.filterDeviceType = value;
    this.isDropdownOpen = false;
    this.filterAssets();
  }

  // Dashboard Stats
  totalAssets = 0;
  stats = {
    workstations: { count: 0, percent: 0 },
    servers: { count: 0, percent: 0 },
    iot: { count: 0, percent: 0 },
    networking: { count: 0, percent: 0 }
  };

  /** Sensor IDs this user is scoped to (from JWT). */
  sensorIds: string[] = [];

  constructor(private api: Api, private cdr: ChangeDetectorRef, private auth: AuthService) {}

  ngOnInit() {
    this.sensorIds = this.auth.getSensorIds();
    this.loadAssets();
    this.loadSubnets();
  }

  loadSubnets() {
    this.api.getIpamSubnets().subscribe({
      next: (data: any) => { this.subnets = Array.isArray(data) ? data : []; },
      error: () => { this.subnets = []; }
    });
  }

  setSubnetFilter(cidr: string) {
    this.filterSubnet = cidr;
    this.isSubnetDropdownOpen = false;
    this.filterAssets();
  }

  getSubnetLabel(): string {
    if (this.filterSubnet === 'all') return 'All Subnets';
    return this.filterSubnet;
  }

  isIpInCidr(ip: string, cidr: string): boolean {
    const [net, prefixStr] = cidr.split('/');
    const prefix = parseInt(prefixStr, 10);
    const ipToNum = (s: string) => s.split('.').reduce((acc, o) => (acc << 8) | parseInt(o, 10), 0) >>> 0;
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    return (ipToNum(ip) & mask) === (ipToNum(net) & mask);
  }

  loadAssets() {
    this.loading = true;
    this.api.getAssets().subscribe({
      next: (data: any) => {
        if (data && Array.isArray(data)) {
          this.assets = data;
        } else if (data && data.error) {
          console.error("Backend error:", data.error);
          this.assets = [];
        } else {
          console.warn("Unexpected data format:", data);
          this.assets = [];
        }
        this.calculateStats();
        this.filterAssets();
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        console.error("HTTP error:", err);
        this.assets = [];
        this.filterAssets();
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  calculateStats() {
    this.totalAssets = this.assets.length;
    
    let workstations = 0;
    let servers = 0;
    let iot = 0;
    let networking = 0;

    this.assets.forEach(a => {
      const type = (a.device_type || 'unknown').toLowerCase();
      if (type === 'server') {
        servers++;
      } else if (['iot', 'printer', 'tv'].includes(type)) {
        iot++;
      } else if (['router', 'network', 'gateway', 'switch', 'firewall'].includes(type)) {
        networking++;
      } else {
        workstations++;
      }
    });

    let pWorkstations = this.totalAssets ? Math.round((workstations / this.totalAssets) * 100) : 0;
    let pServers = this.totalAssets ? Math.round((servers / this.totalAssets) * 100) : 0;
    let pIot = this.totalAssets ? Math.round((iot / this.totalAssets) * 100) : 0;
    let pNetworking = this.totalAssets ? Math.round((networking / this.totalAssets) * 100) : 0;

    if (this.totalAssets > 0) {
      const diff = 100 - (pWorkstations + pServers + pIot + pNetworking);
      if (diff !== 0) {
        const max = Math.max(workstations, servers, iot, networking);
        if (max === workstations) pWorkstations += diff;
        else if (max === servers) pServers += diff;
        else if (max === iot) pIot += diff;
        else pNetworking += diff;
      }
    }

    this.stats = {
      workstations: { count: workstations, percent: pWorkstations },
      servers: { count: servers, percent: pServers },
      iot: { count: iot, percent: pIot },
      networking: { count: networking, percent: pNetworking }
    };
  }

  filterAssets() {
    const term = (this.searchTerm || '').toLowerCase();
    const now = Date.now() / 1000;
    
    this.filteredAssets = this.assets.filter(a => {
      // 0. Subnet Filter
      if (this.filterSubnet !== 'all') {
        if (!a.ip || !this.isIpInCidr(a.ip, this.filterSubnet)) return false;
      }

      // 1. Device Type Filter
      if (this.filterDeviceType !== 'all') {
        const type = (a.device_type || '').toLowerCase();
        let isMatch = type === this.filterDeviceType;
        
        // Handle synonyms for multi-term categories
        if (this.filterDeviceType === 'phone' && type === 'mobile') isMatch = true;
        if (this.filterDeviceType === 'tv' && type === 'media') isMatch = true;
        if (this.filterDeviceType === 'router' && (type === 'gateway' || type === 'firewall' || type === 'switch')) isMatch = true;
        
        if (!isMatch) return false;
      }
      
      // 2. 24h Filter
      if (this.filterLast24h) {
        // last_seen is a unix timestamp in seconds
        if (!a.last_seen || (now - a.last_seen) > 86400) {
          return false;
        }
      }
      
      // 3. Search Term Filter
      if (term) {
        const ip = (a.ip || '').toLowerCase();
        const mac = (a.mac || '').toLowerCase();
        const hostname = (a.hostname || '').toLowerCase();
        const custom_name = (a.custom_name || '').toLowerCase();
        const vendor = (a.vendor || '').toLowerCase();
        const device_type = (a.device_type || '').toLowerCase();
        
        // Hybrid Asset Model: also search inside ip_history JSON for historical IPs
        let historyMatch = false;
        if (a.ip_history && a.ip_history !== '[]') {
          try {
            const history: Array<{ip: string}> = JSON.parse(a.ip_history);
            historyMatch = history.some((entry: {ip: string}) =>
              entry.ip && entry.ip.toLowerCase().includes(term)
            );
          } catch { /* ignore malformed JSON */ }
        }
        
        return ip.includes(term) ||
               mac.includes(term) ||
               hostname.includes(term) ||
               custom_name.includes(term) ||
               vendor.includes(term) ||
               device_type.includes(term) ||
               historyMatch;
      }
      
      return true;
    });
  }

  getDeviceIcon(type: string) {
    switch(type?.toLowerCase()) {
      case 'laptop': return this.MonitorIcon;
      case 'desktop': return this.MonitorIcon;
      case 'mobile': return this.SmartphoneIcon;
      case 'phone': return this.SmartphoneIcon;
      case 'tablet': return this.SmartphoneIcon;
      case 'printer': return this.PrinterIcon;
      case 'router': return this.RouterIcon;
      case 'server': return this.ServerIcon;
      case 'iot': return this.LightbulbIcon;
      default: return this.ServerIcon;
    }
  }

  startEdit(asset: any) {
    this.editingIp = asset.ip;
    this.editNameValue = asset.custom_name || asset.hostname;
  }

  cancelEdit() {
    this.editingIp = null;
  }

  saveEdit(asset: any) {
    this.api.updateAsset(asset.ip, { custom_name: this.editNameValue }).subscribe({
      next: () => {
        asset.custom_name = this.editNameValue;
        this.editingIp = null;
      },
      error: (err) => {
        console.error('Failed to update asset name:', err);
        alert('Failed to update name. Please try again.');
        this.editingIp = null;
      }
    });
  }

  toggleTrusted(asset: any) {
    const newVal = !asset.trusted;
    this.api.setAssetTrusted(asset.ip, newVal).subscribe({
      next: () => {
        asset.trusted = newVal;
        if (newVal) asset.threat_flagged = false;
      },
      error: (err) => console.error('Failed to update trusted flag:', err)
    });
  }

  formatLastSeen(ts: number) {
    if (!ts) return 'Never';
    return new Date(ts * 1000).toLocaleString();
  }

  getRoleClass(role: string): string {
    if (!role) return '';
    const r = role.toLowerCase();
    if (r.includes('server'))   return 'role-server';
    if (r.includes('gateway') || r.includes('router')) return 'role-network';
    if (r.includes('workstation')) return 'role-workstation';
    if (r.includes('iot'))      return 'role-iot';
    if (r.includes('database')) return 'role-database';
    return 'role-default';
  }

  getCriticalityClass(score: number): string {
    if (score >= 70) return 'crit-high';
    if (score >= 40) return 'crit-medium';
    return 'crit-low';
  }

  selectAsset(asset: any) {
    this.selectedAsset = asset;
  }

  closeDrawer() {
    this.selectedAsset = null;
  }

  handleFocus(ip: string) {
    // If we wanted to link to the map focus mode, we could use the Router.
    // For now, in assets page, it could just be an alert or redirect.
  }
}
