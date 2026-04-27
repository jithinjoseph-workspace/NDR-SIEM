import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LucideAngularModule, Search, ShieldCheck, AlertCircle, RefreshCw, Hash } from 'lucide-angular';

@Component({
  selector: 'app-intel',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './intel.html',
  styleUrl: './intel.css'
})
export class Intel {
  indicators = [
    { value: '45.33.22.11', Capability: 'IP_ADDRESS', source: 'AlienVault OTX', confidence: 92, lastSeen: '5m ago' },
    { value: 'evil-cnc.top', Capability: 'DOMAIN', source: 'MISP', confidence: 85, lastSeen: '1h ago' },
    { value: 'f4e2...a1b2', Capability: 'FILE_HASH', source: 'CrowdStrike', confidence: 98, lastSeen: '2d ago' },
  ];

  SearchIcon = Search;
  ShieldCheckIcon = ShieldCheck;
  AlertIcon = AlertCircle;
  RefreshIcon = RefreshCw;
  HashIcon = Hash;
}
