import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LucideAngularModule, Radio } from 'lucide-angular';

/**
 * Sensor Scope Banner
 *
 * Displays a slim banner indicating which sensors the current analyst is scoped to.
 * - If sensor_ids is empty ? renders nothing (user is unrestricted: admin/tenant_admin).
 * - If sensor_ids has values ? shows "Viewing data from: sensor-abc · sensor-xyz".
 *
 * Usage:
 *   <app-sensor-scope-banner [sensorIds]="sensorIds"></app-sensor-scope-banner>
 */
@Component({
  selector: 'app-sensor-scope-banner',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './sensor-scope-banner.html',
  styleUrl: './sensor-scope-banner.css',
})
export class SensorScopeBanner {
  /** Sensor IDs from the decoded JWT. Pass [] to hide the banner. */
  @Input() sensorIds: string[] = [];

  RadioIcon = Radio;

  get hasSensors(): boolean {
    return this.sensorIds.length > 0;
  }
}
