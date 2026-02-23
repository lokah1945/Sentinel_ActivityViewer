import type { Browser, CDPSession } from "playwright";
import { nowIso } from "./sink.js";

type OnEvent = (ev: any) => void;

export class CdpManager {
  private root!: CDPSession;
  private onEvent: OnEvent;
  private bootstrap: string;
  private attached = new Set<string>();

  constructor(onEvent: OnEvent, bootstrap: string) {
    this.onEvent = onEvent;
    this.bootstrap = bootstrap;
  }

  async attach(browser: Browser) {
    this.root = await browser.newBrowserCDPSession();

    await this.root.send("Target.setDiscoverTargets", { discover: true });
    await this.root.send("Target.setAutoAttach", {
      autoAttach: true,
      waitForDebuggerOnStart: false,
      flatten: true,
    });

    this.root.on("Target.attachedToTarget" as any, async (evt: any) => {
      const { sessionId, targetInfo } = evt;
      if (!sessionId || this.attached.has(sessionId)) return;
      this.attached.add(sessionId);

      const kind = targetInfo?.type || "unknown";
      const url = targetInfo?.url || "";

      this.onEvent({
        ts: nowIso(),
        type: "cdp:target_attached",
        target: { kind, url, targetId: targetInfo?.targetId },
      });

      if (["worker", "shared_worker", "service_worker", "other"].includes(kind)) {
        try {
          await this.root.send("Runtime.enable", undefined);
          await this.root.send("Runtime.evaluate", {
            expression: this.bootstrap,
            includeCommandLineAPI: false,
            awaitPromise: false,
          }).catch(() => {});
        } catch (e) {
          this.onEvent({
            ts: nowIso(),
            type: "cdp:inject_error",
            error: String(e),
            target: { kind, url },
          });
        }
      }
    });

    this.root.on("Target.detachedFromTarget" as any, (evt: any) => {
      this.onEvent({
        ts: nowIso(),
        type: "cdp:target_detached",
        sessionId: evt?.sessionId,
      });
    });

    this.root.on("Runtime.consoleAPICalled" as any, (params: any) => {
      try {
        const args = params?.args || [];
        const first = args[0];
        if (
          first?.type === "string" &&
          typeof first?.value === "string" &&
          first.value.startsWith("__AV__|")
        ) {
          const payload = JSON.parse(first.value.slice(7));
          payload._via = "cdp";
          this.onEvent(payload);
        }
      } catch {}
    });

    this.root.on("Runtime.exceptionThrown" as any, (params: any) => {
      this.onEvent({
        ts: nowIso(),
        type: "runtime:exception",
        text: params?.exceptionDetails?.text,
        url: params?.exceptionDetails?.url,
        detail: params?.exceptionDetails?.exception?.description?.slice(0, 500),
      });
    });

    this.onEvent({ ts: nowIso(), type: "cdp:ready" });
  }
}
