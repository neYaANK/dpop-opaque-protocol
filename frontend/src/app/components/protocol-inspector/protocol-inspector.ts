import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-protocol-inspector',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './protocol-inspector.html',
  styleUrl: './protocol-inspector.css',
})
export class ProtocolInspectorComponent {
  get logs() {
    return this.authService.logs;
  }

  constructor(private authService: AuthService) {}

  clearLogs() {
    this.authService.clearLogs();
  }

  asJson(obj: any): string {
    return JSON.stringify(obj, null, 2);
  }

  hasKeys(obj: any): boolean {
    return !!obj && typeof obj === 'object' && Object.keys(obj).length > 0;
  }

  getHeaderEntries(headers?: Record<string, string>): { key: string; value: string }[] {
    if (!headers) return [];
    return Object.entries(headers).map(([key, value]) => ({ key, value }));
  }
}
