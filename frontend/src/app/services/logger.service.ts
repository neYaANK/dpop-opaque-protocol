import { Injectable, signal } from '@angular/core';
import { LogEntry } from './auth.types';

@Injectable({
  providedIn: 'root',
})
export class ProtocolLoggerService {
  private logCounter = 0;
  readonly logs = signal<LogEntry[]>([]);

  addLog(entry: Omit<LogEntry, 'id' | 'time'>) {
    const time = new Date().toLocaleTimeString();
    const newEntry: LogEntry = {
      ...entry,
      id: ++this.logCounter,
      time,
    };
    this.logs.update((prev) => [...prev, newEntry]);
  }

  clearLogs() {
    this.logs.set([]);
  }
}
