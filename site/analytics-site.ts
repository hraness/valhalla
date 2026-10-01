import { type PostHogSiteDefinition, POSTHOG_SCHEMA_VERSION } from "@hraness/posthog";

export const analyticsSite = {
  id: "vhalla",
  canonicalDomain: "vhalla.com",
  allowedHosts: ["vhalla.com", "www.vhalla.com"],
  schemaVersion: POSTHOG_SCHEMA_VERSION,
  routes: [
    { match: "exact", path: "/", pageKind: "home" },
    { match: "prefix", path: "/docs", pageKind: "docs" },
    { match: "prefix", path: "/compare", pageKind: "compare" },
    { match: "prefix", path: "/writing", pageKind: "article", contentGroup: "writing", captureSlug: true },
  ],
  // Private routes suppress events, not just campaign attribution.
  excludedPaths: [{ match: "prefix", path: "/account" }, { match: "prefix", path: "/auth" }],
  sensitivePaths: [{ match: "prefix", path: "/account" }, { match: "prefix", path: "/auth" }],
  customEvents: ["cta clicked", "outbound link opened", "download started", "install command copied"],
} as const satisfies PostHogSiteDefinition;

/** All generated pages, including articles and the real 404, share this include. */
export function withAnalytics(html: string, notFound = false): string {
  if (html.split("</head>").length !== 2) throw new Error("Expected exactly one analytics insertion point");
  const marker = notFound ? ' data-analytics-not-found="true"' : "";
  return html.replace("</head>", `<script src="/analytics.js" defer${marker}></script>\n</head>`);
}

/** Only bounded semantic names reach analytics; URLs and link text are never event IDs. */
export function analyticsCtaForUrl(url: URL): string {
  if (url.hostname.replace(/^www\./, "") === "github.com") return "github";
  if (["/install", "/download"].includes(url.pathname.replace(/\/$/, "")) || url.hash === "#install") return "install";
  if (url.pathname === "/docs" || url.pathname.startsWith("/docs/")) return "docs";
  if (url.pathname === "/compare" || url.pathname.startsWith("/compare/")) return "compare";
  if (url.pathname === "/connect") return "connect";
  if (url.pathname === "/use-cases" || url.hash === "#use") return "use_cases";
  return "get_started";
}
