import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LucideAngularModule, Gavel, Plus, Edit, Trash2, Power } from 'lucide-angular';

@Component({
  selector: 'app-rules',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './rules.html',
  styleUrl: './rules.css'
})
export class Rules {
  rules = [
    { name: 'Brute Force Detection', type: 'SIGMA', severity: 'CRITICAL', status: 'ACTIVE', lastTriggered: '10m ago' },
    { name: 'Unusual Exfiltration', type: 'YARA', severity: 'HIGH', status: 'ACTIVE', lastTriggered: '2h ago' },
    { name: 'Internal Port Scanning', type: 'Suricata', severity: 'MEDIUM', status: 'INACTIVE', lastTriggered: 'Never' },
  ];

  GavelIcon = Gavel;
  PlusIcon = Plus;
  EditIcon = Edit;
  TrashIcon = Trash2;
  PowerIcon = Power;
}
