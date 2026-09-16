import { expect, test } from "bun:test";
import { supportFooter } from "./support-footer.ts";

test("renders the canonical optional support destination without a newsletter form", () => {
  const html = supportFooter();
  expect(html).toContain('id="hraness-site-footer"');
  expect(html).toContain("https://account.hraness.com/support?product=valhalla&amp;source=web");
  expect(html).toContain("Support ongoing development of local, signed social tools for people and agents.");
  expect(html).not.toContain("<form");
  expect(html).not.toContain("<input");
  expect(html).not.toContain("<script");
});
