import { Component, OnInit, OnDestroy, ChangeDetectorRef, ViewChild, ElementRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Websocket } from '../../services/websocket/websocket';
import { LucideAngularModule, Radio, Zap, Activity } from 'lucide-angular';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-live',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './live.html',
  styleUrl: './live.css'
})
export class Live implements OnInit, OnDestroy {
  messages: any[] = [];
  eventCount: number = 0;
  hitCount: number = 0;
  autoScroll: boolean = true;

  RadioIcon = Radio;
  ZapIcon = Zap;
  ActivityIcon = Activity;

  @ViewChild('streamContainer') streamContainer!: ElementRef;

  private subs: Subscription[] = [];

  constructor(
    private ws: Websocket,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    // Listen to all WebSocket messages
    this.subs.push(
      this.ws.messages$.subscribe(msg => {
        if (msg.type === 'agent_status' || msg.type === 'interfaces') return;

        let event = '';
        let data = '';
        let color = 'border-primary/30';

        if (msg.type === 'zeek') {
          event = 'ZEEK';
          data = `${msg.src || '-'} -> ${msg.dst || '-'} [${msg.proto || '-'}] ${msg.service || ''} ${msg.conn_state || ''}`;
          color = 'border-primary/30';
          this.eventCount++;
        } else if (msg.type === 'suricata') {
          event = 'SURICATA';
          data = `${msg.src || '-'} -> ${msg.dst || '-'} [${msg.event_type || '-'}]`;
          color = 'border-secondary/30';
          this.eventCount++;
        } else if (msg.type === 'hit') {
          event = 'HIT';
          data = `Score:${msg.score?.toFixed(0)} | ${msg.severity?.toUpperCase()} | ${msg.tags?.join(', ') || ''} | CID:${msg.cid || '-'}`;
          color = 'border-tertiary/50';
          this.hitCount++;
        }

        this.messages.unshift({
          timestamp: new Date().toLocaleTimeString(),
          event,
          data,
          color,
          raw: msg
        });

        // Keep max 100 messages
        if (this.messages.length > 100) this.messages.pop();
        this.cdr.detectChanges();

        // Auto scroll to top
        if (this.autoScroll && this.streamContainer) {
          this.streamContainer.nativeElement.scrollTop = 0;
        }
      })
    );
  }

  clearMessages() {
    this.messages = [];
    this.eventCount = 0;
    this.hitCount = 0;
    this.cdr.detectChanges();
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
  }
}
