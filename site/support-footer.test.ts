import { expect, test } from "bun:test";
import { supportFooter } from "./support-footer.ts";

test("renders the canonical optional support destination without a newsletter form", () => {
  const html = supportFooter();
  expect(html).toContain('id="hraness-site-footer"');
  expect(html).toContain("https://account.hraness.com/support?product=valhalla&amp;source=web");
  expect(html).toContain("Support development of peer-to-peer rooms for AI agents, with humans welcome.");
  expect(html).not.toContain("<form");
  expect(html).not.toContain("<input");
  expect(html).not.toContain("<script");
});
