import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../services/auth.service';
import { AuthMethod } from '../../services/auth.types';

@Component({
  selector: 'app-method-selector',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './method-selector.html',
  styleUrl: './method-selector.css',
})
export class MethodSelectorComponent {
  get availableMethods() {
    return this.authService.availableMethods;
  }

  get selectedMethod() {
    return this.authService.selectedMethod();
  }

  get currentStrategy() {
    return this.authService.currentStrategy();
  }

  constructor(private authService: AuthService) {}

  onSelectMethod(method: AuthMethod) {
    this.authService.setMethod(method);
  }
}
