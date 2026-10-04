import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { docs } from "./pages.ts";
import { renderHome } from "./home.ts";
import { renderDoc } from "./docs.ts";
import { daemonRelease, vhallaPlatforms } from "./platform-install.ts";

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

test("current pages select the daemon while preserving a separate default installer block", () => {
  for (const [page, count] of [[home, 1], [gettingStarted, 2]] as const) {
    expect(page.match(/data-hraness-platform-install=""/g)?.length).toBe(count);
    expect(page).toContain('<script src="/platform-install-client.js" defer></script>');
    const tabs = [...page.matchAll(/class="hraness-platform-install__tab-label">([^<]+)</g)].map(match => match[1]);
    expect(tabs).toEqual(Array.from({ length: count }, () => ["macOS", "Linux", "Windows"]).flat());
    expect(page).toContain("irm https://vhalla.com/install.ps1 | iex");
    expect(page).toContain(`VHALLA_VERSION=${daemonRelease}`);
    expect(page).toContain("automatic updates disabled");
    expect(page).toContain("private-room member commands only");
    expect(page).not.toContain("<!-- vhalla-platform-");
  }
});
