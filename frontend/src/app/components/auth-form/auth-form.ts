import { Component, signal, effect } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { AuthService } from '../../services/auth.service';
import { AuthResult } from '../../services/auth.types';

@Component({
  selector: 'app-auth-form',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './auth-form.html',
  styleUrl: './auth-form.css',
})
export class AuthFormComponent {
  mode = signal<'login' | 'register'>('login');
  username = signal('');
  password = signal('');
  isLoading = signal(false);
  errorMessage = signal<string | null>(null);
  successMessage = signal<string | null>(null);
  lastResult = signal<AuthResult | null>(null);

  constructor(private authService: AuthService) {
    effect(() => {
      this.authService.selectedMethod();
      this.errorMessage.set(null);
      this.successMessage.set(null);
      this.lastResult.set(null);
    });
  }

  switchMode(newMode: 'login' | 'register') {
    this.mode.set(newMode);
    this.errorMessage.set(null);
    this.successMessage.set(null);
  }

  async onSubmit() {
    const user = this.username().trim();
    const pass = this.password();

    if (!user || !pass) {
      this.errorMessage.set('Please enter both username and password');
      return;
    }

    this.isLoading.set(true);
    this.errorMessage.set(null);
    this.successMessage.set(null);

    try {
      if (this.mode() === 'register') {
        const result = await this.authService.register(user, pass);
        this.lastResult.set(result);
        this.successMessage.set(result.message || 'Registration successful!');
      } else {
        const result = await this.authService.login(user, pass);
        this.lastResult.set(result);
        this.successMessage.set(result.message || `Login for ${result.username || user} succeeded!`);
      }
    } catch (err: any) {
      const serverError = err?.error?.error || err?.message || 'Error performing operation';
      this.errorMessage.set(serverError);
    } finally {
      this.isLoading.set(false);
    }
  }
}
