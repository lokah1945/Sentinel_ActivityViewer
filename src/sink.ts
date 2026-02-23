import fs from "node:fs";
import path from "node:path";
import type { AvEvent } from "./types.js";

export class JsonlSink {
  private stream: fs.WriteStream;
  private count = 0;
  private recentHashes = new Set<string>();
  private lastCleanup = Date.now();

  constructor(filePath: string) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    this.stream = fs.createWriteStream(filePath, { flags: "a" });
  }

  write(ev: AvEvent) {
    const hash = this.quickHash(ev);
    const now = Date.now();
    if (hash && this.recentHashes.has(hash)) return;
    if (hash) {
      this.recentHashes.add(hash);
      if (now - this.lastCleanup > 2000) {
        this.recentHashes.clear();
        this.lastCleanup = now;
      }
    }
    this.stream.write(JSON.stringify(ev) + "\n");
    this.count++;
  }

  private quickHash(ev: AvEvent): string | null {
    if (ev.type !== "browser:access") return null;
    return `${ev.api}|${ev.action}|${ev.context?.url || ""}`;
  }

  getCount() { return this.count; }
  close() { this.stream.end(); }
}

export function nowIso() {
  return new Date().toISOString();
}
