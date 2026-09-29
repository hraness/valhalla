import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { docs } from "./pages.ts";
import { renderHome } from "./home.ts";
import { renderDoc } from "./docs.ts";
import { vhallaPlatforms } from "./platform-install.ts";

const index = await readFile(new URL("./index.html", import.meta.url), "utf8");
const home = renderHome(index);
const gettingStarted = renderDoc(docs.find(page => page.slug === "getting-started")!, index);

test("install tabs list macOS, Linux and Windows with the commands the installers serve", () => {
  expect(vhallaPlatforms.map(target => target.id)).toEqual(["macos", "linux", "windows"]);
  const [macos, linux, windows] = vhallaPlatforms;
  expect(macos!.command).toBe("curl -fsSL https://vhalla.com/install.sh | sh");
  expect(linux!.command).toBe(macos!.command);
  expect(windows!.command).toBe("irm https://vhalla.com/install.ps1 | iex");
  expect(windows!.shell).toBe("PowerShell");
  expect(macos!.alternatives).toEqual([{ label: "Homebrew", command: "brew install hraness/tap/vhalla", shell: "Terminal" }]);
  expect(windows!.note).toContain("WSL2");
});

test("home and getting started render the shared block once, with no inline script", () => {
  for (const page of [home, gettingStarted]) {
    expect(page.match(/data-hraness-platform-install=""/g)?.length).toBe(1);
    expect(page).toContain('<script src="/platform-install-client.js" defer></script>');
    const tabs = [...page.matchAll(/class="hraness-platform-install__tab-label">([^<]+)</g)].map(match => match[1]);
    expect(tabs).toEqual(["macOS", "Linux", "Windows"]);
    expect(page).toContain("irm https://vhalla.com/install.ps1 | iex");
    expect(page).toContain("brew install hraness/tap/vhalla");
    expect(page).not.toContain("<!-- vhalla-platform-");
  }
});
