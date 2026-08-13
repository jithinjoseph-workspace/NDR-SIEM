import { Component, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { RouterModule } from '@angular/router';
import { Sidebar } from '../sidebar/sidebar';

@Component({
  selector: 'app-analyst-layout',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [RouterModule, Sidebar],
  templateUrl: './analyst-layout.html',
  styleUrl: './analyst-layout.css',
})
export class AnalystLayout {}
