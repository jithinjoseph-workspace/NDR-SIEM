import { Component, Input, Output, EventEmitter, OnChanges, SimpleChanges, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';
import { ArkimeService } from '../../services/arkime/arkime';
import {
  LucideAngularModule,
  Network,
  Package,
  X,
  Laptop,
  Monitor,
  Smartphone,
  Tablet,
  Cpu,
  Printer,
  Tv,
  HelpCircle,
  Globe,
  Server,
  Router,
  TriangleAlert,
  Users,
  Download,
  ExternalLink,
  Edit2,
  Check
} from 'lucide-angular';

@Component({
  selector: 'app-device-drawer',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './device-drawer.html',
  styleUrl: './device-drawer.css',
})
export class DeviceDrawer implements OnChanges {
  @Input() node: any = null;
  @Input() focusModeActive: boolean = false;
  @Output() closeDrawer = new EventEmitter<void>();
  @Output() focusRequested = new EventEmitter<string>();

  drawerTab: string = 'overview';

  selectedNodeConnections: any[] = [];
  loadingConnections = false;

  selectedNodeAlerts: any[] = [];
  loadingAlerts = false;

  pcapSessions: any[] = [];
  pcapLoading = false;
  pcapError = '';

  NetworkIcon = Network;
  PackageIcon = Package;
  XIcon = X;
  DownloadIcon = Download;
  ExternalLinkIcon = ExternalLink;
  EditIcon = Edit2;
  CheckIcon = Check;

  isEditingName = false;
  editNameValue = '';

  constructor(private api: Api, private cdr: ChangeDetectorRef, private arkime: ArkimeService) {}

  ngOnChanges(changes: SimpleChanges) {
    if (changes['node']) {
      this.setDrawerTab(this.drawerTab);
    }
  }

  setDrawerTab(tab: string) {
    this.drawerTab = tab;
    if (!this.node) return;

    if (tab === 'connections') {
      this.loadNodeConnections(this.node.active_ip || this.node.id || this.node.ip);
    } else if (tab === 'alerts') {
      this.loadNodeAlerts(this.node.active_ip || this.node.id || this.node.ip);
    } else if (tab === 'pcaps') {
      this.loadPcapSessions(this.node.active_ip || this.node.id || this.node.ip);
    }
  }

  loadNodeConnections(ip: string) {
    this.loadingConnections = true;
    this.selectedNodeConnections = [];
    this.api.getNetworkMapNode(ip).subscribe({
      next: (data: any) => {
        const edges = data.edges || [];
        this.selectedNodeConnections = edges.map((e: any) => ({
           peer: e.source === ip ? e.target : e.source,
           connections: e.connections,
           protocols: e.protocols || []
        }));
        this.loadingConnections = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loadingConnections = false;
        this.cdr.detectChanges();
      }
    });
  }

  loadNodeAlerts(ip: string) {
    this.loadingAlerts = true;
    this.selectedNodeAlerts = [];
    this.api.getAlerts().subscribe({
      next: (hits: any[]) => {
        this.selectedNodeAlerts = hits.filter((h: any) => h.src_ip === ip || h.dst_ip === ip);
        this.loadingAlerts = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loadingAlerts = false;
        this.cdr.detectChanges();
      }
    });
  }

  loadPcapSessions(ip: string) {
    this.pcapLoading = true;
    this.pcapSessions = [];
    this.pcapError = '';

    this.arkime.getSessions({ ip, limit: 10 }).subscribe({
      next: (res: any) => {
        this.pcapSessions = res.sessions || res.data || [];
        this.pcapLoading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.pcapError = 'Failed to load PCAP sessions';
        this.pcapLoading = false;
        this.cdr.detectChanges();
      }
    });
  }

  downloadPcap(sessionId: string) {
    this.arkime.downloadPcap(sessionId);
  }

  toggleFocus() {
    if (!this.node) return;
    this.focusRequested.emit(this.node.id || this.node.ip);
  }

  onClose() {
    this.closeDrawer.emit();
  }

  startEditName() {
    this.isEditingName = true;
    this.editNameValue = this.node.custom_name || this.node.hostname || this.node.label || '';
  }

  saveName() {
    const ip = this.node.active_ip || this.node.ip || this.node.id;
    if (!ip) return;

    this.api.updateAsset(ip, { custom_name: this.editNameValue }).subscribe({
      next: () => {
        this.node.custom_name = this.editNameValue;
        this.node.label = this.editNameValue;
        this.isEditingName = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.isEditingName = false;
        this.cdr.detectChanges();
      }
    });
  }

  cancelEditName() {
    this.isEditingName = false;
  }

  isInternalNode(node: any): boolean {
    if (node?.is_internal !== undefined) return node.is_internal;
    const ip = node?.active_ip || node?.ip || node?.id || '';
    if (!ip) return false;
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.')) return true;
    if (ip.startsWith('172.')) {
      const parts = ip.split('.');
      if (parts.length > 1) {
        const second = parseInt(parts[1], 10);
        if (second >= 16 && second <= 31) return true;
      }
    }
    return false;
  }

  getDrawerIcon(node: any): any {
    const type = node?.type || node?.device_type;
    if (type === 'cluster') return Users;
    if (type === 'laptop') return Laptop;
    if (type === 'desktop') return Monitor;
    if (type === 'phone' || type === 'mobile') return Smartphone;
    if (type === 'tablet') return Tablet;
    if (type === 'iot') return Cpu;
    if (type === 'printer') return Printer;
    if (type === 'tv' || type === 'media') return Tv;
    if (type === 'server') return Server;
    if (type === 'router' || type === 'gateway' || type === 'firewall' || type === 'switch') return Router;

    const isInternal = this.isInternalNode(node);
    if (isInternal) return Router;
    if (node?.threat) return TriangleAlert;
    return isInternal ? HelpCircle : Globe;
  }

  getNodeTypeClass(node: any): string {
    if (node?.threat) return 'threat';
    return this.isInternalNode(node) ? 'internal' : 'external';
  }
}
