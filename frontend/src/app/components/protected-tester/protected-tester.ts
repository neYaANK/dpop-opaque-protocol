import { Component, signal, effect } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../services/auth.service';
import { ProtectedResponse } from '../../services/auth.types';

@Component({
  selector: 'app-protected-tester',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './protected-tester.html',
  styleUrl: './protected-tester.css',
})
export class ProtectedTesterComponent {
  isTestingProtected = signal(false);
  protectedResult = signal<ProtectedResponse | null>(null);
  protectedErrorMessage = signal<string | null>(null);

  constructor(private authService: AuthService) {
    effect(() => {
      this.authService.selectedMethod();
      this.protectedResult.set(null);
      this.protectedErrorMessage.set(null);
    });
  }

  asJson(obj: any): string {
    return JSON.stringify(obj, null, 2);
  }

  async onTestProtectedGet() {
    this.isTestingProtected.set(true);
    this.protectedResult.set(null);
    this.protectedErrorMessage.set(null);

    try {
      const response = await this.authService.testProtectedGet();
      this.protectedResult.set(response);
    } catch (err: any) {
      const msg = err?.error?.error || err?.message || 'Protected GET request failed';
      this.protectedErrorMessage.set(msg);
    } finally {
      this.isTestingProtected.set(false);
    }
  }

  async onTestProtectedPost() {
    this.isTestingProtected.set(true);
    this.protectedResult.set(null);
    this.protectedErrorMessage.set(null);

    const payload = {
      action: 'UPDATE_SETTINGS',
      preferences: { theme: 'dark', notifications: true },
      clientTimestamp: new Date().toISOString(),
      randomNonce: Math.random().toString(36).substring(2, 10),
    };

    try {
      const response = await this.authService.testProtectedPost(payload);
      this.protectedResult.set(response);
    } catch (err: any) {
      const msg = err?.error?.error || err?.message || 'Protected POST request failed';
      this.protectedErrorMessage.set(msg);
    } finally {
      this.isTestingProtected.set(false);
    }
  }
}
