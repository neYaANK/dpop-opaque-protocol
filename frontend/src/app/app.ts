import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MethodSelectorComponent } from './components/method-selector/method-selector';
import { AuthFormComponent } from './components/auth-form/auth-form';
import { ProtectedTesterComponent } from './components/protected-tester/protected-tester';
import { ProtocolInspectorComponent } from './components/protocol-inspector/protocol-inspector';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    CommonModule,
    MethodSelectorComponent,
    AuthFormComponent,
    ProtectedTesterComponent,
    ProtocolInspectorComponent,
  ],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {}

