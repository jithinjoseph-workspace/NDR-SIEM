import { Component, OnInit, OnDestroy, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import {
  LucideAngularModule,
  Cpu, MemoryStick, RefreshCw,
} from 'lucide-angular';
import { Api } from '../../../services/api/api';

@Component({
  selector: 'app-telemetry',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './telemetry.html',
  styleUrl: './telemetry.css',
})
export class Telemetry implements OnInit, OnDestroy {
  CpuIcon          = Cpu;
  MemoryStickIcon  = MemoryStick;
  RefreshIcon      = RefreshCw;

  telemetryData: any = null;
  private telemetryInterval: ReturnType<typeof setInterval> | null = null;

  constructor(private api: Api, private cdr: ChangeDetectorRef) {}

  ngOnInit() {
    this.loadTelemetry();
    this.telemetryInterval = setInterval(() => this.loadTelemetry(), 5000);
  }

  ngOnDestroy() {
    if (this.telemetryInterval !== null) clearInterval(this.telemetryInterval);
  }

  loadTelemetry() {
    this.api.getPlatformTelemetry().subscribe({
      next: (data: any) => { this.telemetryData = data; this.cdr.detectChanges(); },
    });
  }
}
