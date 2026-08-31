import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { OpaqueService, RegisterResult, LoginResult } from './services/opaque';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {
  mode = signal<'login' | 'register'>('login');
  username = signal('');
  password = signal('');
  isLoading = signal(false);
  errorMessage = signal<string | null>(null);
  successMessage = signal<string | null>(null);
  lastResult = signal<RegisterResult | LoginResult | null>(null);

  constructor(private opaqueService: OpaqueService) {}

  switchMode(newMode: 'login' | 'register') {
    this.mode.set(newMode);
    this.errorMessage.set(null);
    this.successMessage.set(null);
  }

  async onSubmit() {
    const user = this.username().trim();
    const pass = this.password();

    if (!user || !pass) {
      this.errorMessage.set('Enter username and password');
      return;
    }

    this.isLoading.set(true);
    this.errorMessage.set(null);
    this.successMessage.set(null);

    try {
      if (this.mode() === 'register') {
        const result = await this.opaqueService.register(user, pass);
        this.lastResult.set(result);
        this.successMessage.set('Registration successful!');
      } else {
        const result = await this.opaqueService.login(user, pass);
        this.lastResult.set(result);
        this.successMessage.set(`Login for ${result.username} succeeded!`);
      }
    } catch (err: any) {
      console.error('Operation error:', err);
      const serverError = err?.error?.error || err?.message || 'Error performing operation';
      this.errorMessage.set(serverError);
    } finally {
      this.isLoading.set(false);
    }
  }
}
