import type { BrowserContext, Route } from "playwright";

export async function installScriptRewriter(context: BrowserContext, bootstrap: string) {
  await context.route("**/*", async (route: Route) => {
    const req = route.request();
    if (req.resourceType() !== "script") return route.continue();

    const url = req.url();
    if (!url.startsWith("http://") && !url.startsWith("https://")) return route.continue();

    try {
      const res = await route.fetch();
      const ct = (res.headers()["content-type"] || "").toLowerCase();

      const isJs = ct.includes("javascript") || ct.includes("ecmascript") ||
                   ct.includes("text/plain") ||
                   url.endsWith(".js") || url.endsWith(".mjs") || url.endsWith(".cjs") ||
                   url.includes(".js?");

      if (!isJs) return route.fulfill({ response: res });

      const body = await res.text();
      const patched = `${bootstrap}\n;\n${body}`;
      const hdrs = { ...res.headers() };
      hdrs["content-length"] = String(Buffer.byteLength(patched));
      delete hdrs["content-security-policy"];
      delete hdrs["content-security-policy-report-only"];

      await route.fulfill({ response: res, body: patched, headers: hdrs });
    } catch {
      await route.continue();
    }
  });
}
