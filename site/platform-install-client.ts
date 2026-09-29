// Enhances the static PlatformInstall blocks rendered by platform-install.ts:
// reveals the tab row and Copy buttons, selects the visitor's operating
// system, and announces copy results. Mirrors the design-kit React component.
import { detectPlatform, matchDetectedPlatform } from "@hraness/design-kit";

type ClipboardWriter = Readonly<{ writeText: (value: string) => Promise<void> }>;

async function copyText(value: string, clipboard: ClipboardWriter | undefined, fallback: () => boolean): Promise<boolean> {
  if (clipboard !== undefined) {
    try {
      await clipboard.writeText(value);
      return true;
    } catch {
      // A denied or unavailable async clipboard falls through to selection-based copy.
    }
  }
  try {
    return fallback();
  } catch {
    return false;
  }
}

const COPY_RESET_MS = 2000;

function selectContents(element: HTMLElement, documentValue: Document): void {
  try {
    const selection = documentValue.getSelection();
    if (selection === null) return;
    const range = documentValue.createRange();
    range.selectNodeContents(element);
    selection.removeAllRanges();
    selection.addRange(range);
  } catch {
    // Selection is a convenience; the failure is still announced.
  }
}

export function initializePlatformInstalls(documentValue: Document, navigatorValue: Navigator): void {
  for (const root of documentValue.querySelectorAll<HTMLElement>("[data-hraness-platform-install]")) {
    if (root.dataset.enhanced === "true") continue;
    const tablist = root.querySelector<HTMLElement>("[role=tablist]");
    const status = root.querySelector<HTMLElement>(":scope > [role=status]");
    if (tablist === null || status === null) continue;
    const tabs = [...tablist.querySelectorAll<HTMLButtonElement>("[role=tab]")];
    const panels = [...root.querySelectorAll<HTMLElement>("[role=tabpanel]")];
    const ids = tabs.map((tab) => tab.dataset.platform ?? "");
    if (tabs.length === 0 || tabs.length !== panels.length) continue;
    let chosen = false;

    const select = (id: string, source: "default" | "detected" | "chosen", focus: boolean) => {
      root.dataset.selectedPlatform = id;
      root.dataset.selectionSource = source;
      for (const tab of tabs) {
        const selected = tab.dataset.platform === id;
        tab.setAttribute("aria-selected", String(selected));
        tab.tabIndex = selected ? 0 : -1;
        if (selected && focus) tab.focus();
      }
      for (const panel of panels) panel.hidden = panel.dataset.platform !== id;
    };

    for (const tab of tabs) {
      tab.addEventListener("click", () => {
        chosen = true;
        select(tab.dataset.platform ?? ids[0]!, "chosen", false);
      });
    }
    tablist.addEventListener("keydown", (event) => {
      const index = ids.indexOf(root.dataset.selectedPlatform ?? "");
      let next: number;
      switch (event.key) {
        case "ArrowRight": next = (index + 1) % ids.length; break;
        case "ArrowLeft": next = (index - 1 + ids.length) % ids.length; break;
        case "Home": next = 0; break;
        case "End": next = ids.length - 1; break;
        default: return;
      }
      event.preventDefault();
      chosen = true;
      select(ids[next]!, "chosen", true);
    });

    let resetTimer: ReturnType<typeof setTimeout> | undefined;
    for (const button of root.querySelectorAll<HTMLButtonElement>("[data-platform-install-copy]")) {
      const block = button.closest<HTMLElement>(".hraness-platform-install__command");
      const code = block?.querySelector<HTMLElement>("pre");
      const label = button.querySelector<HTMLElement>("[data-platform-install-copy-label]");
      if (block === null || block === undefined || code === null || code === undefined || label === null) continue;
      const subject = code.getAttribute("aria-label") ?? "install command";
      const commandText = code.textContent ?? "";
      button.hidden = false;
      button.addEventListener("click", async () => {
        let clipboard: ClipboardWriter | undefined;
        try {
          clipboard = navigatorValue.clipboard;
        } catch {
          clipboard = undefined;
        }
        const ok = await copyText(commandText, clipboard, () => {
          selectContents(code, documentValue);
          try {
            return documentValue.execCommand("copy");
          } catch {
            return false;
          }
        });
        if (!ok) selectContents(code, documentValue);
        for (const other of root.querySelectorAll<HTMLElement>("[data-copy-state]")) other.dataset.copyState = "idle";
        for (const other of root.querySelectorAll<HTMLElement>("[data-platform-install-copy-label]")) other.textContent = "Copy";
        block.dataset.copyState = ok ? "copied" : "failed";
        button.dataset.copyState = ok ? "copied" : "failed";
        label.textContent = ok ? "Copied" : "Select to copy";
        status.textContent = ok
          ? `Copied the ${subject}.`
          : `Copying failed. The ${subject} is selected; copy it with your keyboard.`;
        if (resetTimer !== undefined) clearTimeout(resetTimer);
        resetTimer = setTimeout(() => {
          block.dataset.copyState = "idle";
          button.dataset.copyState = "idle";
          label.textContent = "Copy";
          status.textContent = "";
        }, COPY_RESET_MS);
      });
    }

    tablist.hidden = false;
    root.dataset.enhanced = "true";
    select(ids[0]!, "default", false);
    const match = matchDetectedPlatform(detectPlatform(navigatorValue), ids);
    if (match !== null && !chosen) select(match, "detected", false);
  }
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
  initializePlatformInstalls(document, navigator);
}
