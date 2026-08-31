import fs from 'node:fs';
import path from 'node:path';

const DB_FILE = path.join(process.cwd(), 'users.json');

interface UserRecord {
  registrationRecord: string;
}

class SimpleDB {
  private users = new Map<string, UserRecord>();

  constructor() {
    this.load();
  }

  private load() {
    if (fs.existsSync(DB_FILE)) {
      try {
        const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
        this.users = new Map(Object.entries(data));
        console.log(`Loaded ${this.users.size} users from users.json`);
      } catch (e) {
        console.error('Failed to parse users.json');
      }
    }
  }

  private save() {
    const obj = Object.fromEntries(this.users.entries());
    fs.writeFileSync(DB_FILE, JSON.stringify(obj, null, 2), 'utf-8');
  }

  public get(username: string): UserRecord | undefined {
    return this.users.get(username);
  }

  public set(username: string, record: UserRecord) {
    this.users.set(username, record);
    this.save();
  }

  public has(username: string): boolean {
    return this.users.has(username);
  }
}

export const db = new SimpleDB();