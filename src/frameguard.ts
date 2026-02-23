import type { BrowserContext, Frame, Page, Worker } from "playwright";
import fs from "node:fs";
import path from "node:path";
import { nowIso } from "./sink.js";
import type { ContextNode } from "./types.js";

export class ContextMap {
  nodes = new Map<string, ContextNode>();

  upsert(n: ContextNode) {
    this.nodes.set(n.id, { ...(this.nodes.get(n.id) || ({} as any)), ...n });
  }

  toArray(): ContextNode[] {
    return Array.from(this.nodes.values());
  }

  getMaxDepth(): number {
    let max = 0;
    for (const n of this.nodes.values()) if (n.depth > max) max = n.depth;
    return max;
  }

  countByKind(): Record<string, number> {
    const c: Record<string, number> = {};
    for (const n of this.nodes.values()) c[n.kind] = (c[n.kind] || 0) + 1;
    return c;
  }

  save(filePath: string) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(
      filePath,
      JSON.stringify(
        {
          ts: nowIso(),
          summary: {
            totalContexts: this.nodes.size,
            byKind: this.countByKind(),
            maxIframeDepth: this.getMaxDepth(),
          },
          contexts: this.toArray(),
        },
        null,
        2
      )
    );
  }
}

function frameDepth(f: Frame): number {
  let d = 0,
    x: Frame | null = f;
  while (x?.parentFrame()) {
    d++;
    x = x.parentFrame();
  }
  return d;
}

async function getFrameFlags(f: Frame): Promise<Record<string, any>> {
  try {
    const el = await f.frameElement();
    const box = await el.boundingBox().catch(() => null);
    const attrs = await el
      .evaluate((node: Element) => ({
        sandbox: node.getAttribute("sandbox"),
        allow: node.getAttribute("allow"),
        width: node.getAttribute("width"),
        height: node.getAttribute("height"),
        src: (node as HTMLIFrameElement).src,
        hasSrcdoc: !!(node as HTMLIFrameElement).srcdoc,
        hidden: (node as HTMLElement).hidden,
        display: getComputedStyle(node).display,
        visibility: getComputedStyle(node).visibility,
        opacity: getComputedStyle(node).opacity,
      }))
      .catch(() => ({}));
    return {
      ...attrs,
      zeroSize: box ? box.width === 0 || box.height === 0 : null,
      tinySize: box ? box.width < 2 && box.height < 2 : null,
      boundingBox: box,
    };
  } catch {
    return {};
  }
}

export function installFrameGuard(
  context: BrowserContext,
  map: ContextMap,
  onEvent: (ev: any) => void
) {
  let pageCounter = 0;

  function hookPage(page: Page, kind: "page" | "popup") {
    const pid = `${kind}:${++pageCounter}:${page.url().slice(0, 80)}`;
    map.upsert({
      id: pid,
      kind,
      url: page.url(),
      depth: 0,
      flags: {},
      createdAt: nowIso(),
    });
    onEvent({ ts: nowIso(), type: "inventory:page", id: pid, kind, url: page.url() });

    page.on("frameattached", async (f) => {
      const depth = frameDepth(f);
      const fid = `frame:d${depth}:${f.name() || "anon"}:${Math.random().toString(36).slice(2, 8)}`;
      const flags = await getFrameFlags(f);

      const suspicious = !!(
        flags.zeroSize ||
        flags.tinySize ||
        flags.hidden ||
        flags.display === "none" ||
        flags.visibility === "hidden" ||
        flags.opacity === "0" ||
        flags.hasSrcdoc ||
        (typeof flags.src === "string" &&
          (flags.src.startsWith("blob:") || flags.src.startsWith("data:")))
      );

      map.upsert({
        id: fid,
        kind: "frame",
        url: f.url(),
        parentId: pid,
        depth,
        flags: { ...flags, suspicious },
        createdAt: nowIso(),
      });
      onEvent({
        ts: nowIso(),
        type: "inventory:frame",
        id: fid,
        parentId: pid,
        depth,
        url: f.url(),
        flags: { ...flags, suspicious },
      });
    });

    page.on("framenavigated", (f) => {
      onEvent({
        ts: nowIso(),
        type: "inventory:frame_navigated",
        url: f.url(),
        name: f.name(),
        depth: frameDepth(f),
      });
    });

    page.on("framedetached", (f) => {
      onEvent({
        ts: nowIso(),
        type: "inventory:frame_detached",
        url: f.url(),
        name: f.name(),
      });
    });

    page.on("popup", (pop) => {
      onEvent({ ts: nowIso(), type: "popup:opened", opener: pid, url: pop.url() });
      hookPage(pop, "popup");
    });

    page.on("worker", (w: Worker) => {
      const wid = `worker:${w.url().slice(0, 60)}:${Math.random().toString(36).slice(2, 8)}`;
      map.upsert({
        id: wid,
        kind: "worker",
        url: w.url(),
        parentId: pid,
        depth: 0,
        flags: {},
        createdAt: nowIso(),
      });
      onEvent({ ts: nowIso(), type: "inventory:worker", id: wid, parentId: pid, url: w.url() });
    });
  }

  context.on("page", (p) => hookPage(p, "page"));

  context.on("serviceworker", (sw) => {
    const sid = `sw:${sw.url().slice(0, 60)}:${Math.random().toString(36).slice(2, 8)}`;
    map.upsert({
      id: sid,
      kind: "service_worker",
      url: sw.url(),
      depth: 0,
      flags: {},
      createdAt: nowIso(),
    });
    onEvent({ ts: nowIso(), type: "inventory:service_worker", id: sid, url: sw.url() });
  });
}
