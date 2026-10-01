import { ctaClickedProperties } from "@hraness/posthog/event";
import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { classifyAnalyticsRoute } from "@hraness/posthog";
import { checkPostHogContract, runPostHogHarness } from "@hraness/posthog/testing";
import { analyticsSite, withAnalytics, analyticsCtaForUrl } from "./analytics-site";

test("real SDK preserves the portfolio analytics contract", () => {
  expect(checkPostHogContract({ site: analyticsSite, sensitivePath: "/account", customEvents: [{ event: "cta clicked", properties: { cta: "quickstart", placement: "nav" } }, { event: "outbound link opened", properties: { target_host: "github.com", placement: "nav" } }, { event: "download started", properties: { platform: "web", artifact: "benchmark", placement: "inline" } }] }).violations).toEqual([]);
});
test("routes retain public paths and reject preview hosts", () => {
  expect(classifyAnalyticsRoute(analyticsSite, "https://vhalla.com/docs/")?.page_kind).toBe("docs");
  expect(classifyAnalyticsRoute(analyticsSite, "https://vhalla.com/writing/example")?.content_slug).toBe("example");
  expect(classifyAnalyticsRoute(analyticsSite, "https://valhalla-preview.vercel.app/")).toBeNull();
});
test("all generated pages and the 404 inherit analytics", () => {
  const build = readFileSync(new URL("./build.ts", import.meta.url), "utf8");
  expect(build).toContain('const html = withAnalytics(renderMarketingCopy(');
  expect(build).toContain('data-analytics-not-found="true"');
  expect(withAnalytics("<head></head>")).toContain('src="/analytics.js"');
});
test("CSP permits only same-origin code and the two required services", () => {
  const config = JSON.parse(readFileSync(new URL("../vercel.json", import.meta.url), "utf8"));
  const csp = config.headers[0].headers.find((h: { key: string }) => h.key === "Content-Security-Policy").value;
  expect(csp).toContain("script-src 'self'");
  expect(csp).toContain("connect-src 'self' https://us.i.posthog.com https://account.hraness.com");
});

test("CTA identifiers describe known destinations and satisfy the bounded event schema", () => {
  for (const [path, expected] of [["https://github.com/hraness/repo", "github"], ["/install", "install"], ["/docs/guide", "docs"], ["/compare/tool", "compare"], ["/#use", "use_cases"], ["/", "get_started"]]) {
    const cta = analyticsCtaForUrl(new URL(path!, `https://${analyticsSite.canonicalDomain}`));
    expect(cta).toBe(expected!);
    expect(ctaClickedProperties({ cta, placement: "nav" })).not.toBeNull();
  }
});


test("real SDK redacts encoded identifiers before sending paths and exceptions", () => {
  const encodedAddress = "encodedprivacycanary%2540example.com";
  const origin = `https://${analyticsSite.canonicalDomain}`;
  const result = runPostHogHarness({
    site: analyticsSite,
    scenarios: [
      {
        href: `${origin}/`,
        referrer: "",
        captures: [
          { event: "$pageview" },
          { event: "$exception", error: { name: "TypeError", message: `Failed for ${encodedAddress}, +@a.aa, %2B%40a.aa` } },
        ],
      },
      {
        href: `${origin}/docs/${encodedAddress}`,
        referrer: "",
        captures: [{ event: "$pageview" }],
      },
    ],
  });
  expect(result.sent.some((event) => event.event === "$pageview")).toBe(true);
  expect(result.sent.some((event) => event.event === "$exception")).toBe(true);
  expect(JSON.stringify(result.sent)).not.toContain("encodedprivacycanary");
  expect(JSON.stringify(result.sent)).not.toContain("+@a.aa");
  expect(JSON.stringify(result.sent)).not.toContain("%2B%40a.aa");
});


test("private navigation is excluded after public analytics initialization", () => {
  const origin = `https://${analyticsSite.canonicalDomain}`;
  const privatePaths = ["/account", "/%61ccount", "/auth", "/%61uth"];
  for (const path of privatePaths) {
    expect(classifyAnalyticsRoute(analyticsSite, `${origin}${path}/private-route-canary`)).toBeNull();
  }
  const result = runPostHogHarness({
    site: analyticsSite,
    scenarios: [
      { href: `${origin}/`, referrer: "", captures: [{ event: "$pageview" }] },
      ...privatePaths.map((path) => ({
        href: `${origin}${path}/private-route-canary`,
        referrer: "",
        captures: [{ event: "$pageview" }, { event: "$pageleave" }, { event: "$exception", error: { name: "Error", message: "private-route-canary" } }],
      })),
    ],
  });
  expect(result.sent.some((event) => event.event === "$pageview")).toBe(true);
  expect(JSON.stringify(result.sent)).not.toContain("private-route-canary");
});
