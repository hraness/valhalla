// Progressive enhancement of AgentSetupPrompt's public hooks. Presentation
// stays in the shared compiled stylesheet; no React client runtime is bundled.
import { copyAndOpen, copyText, legacyCopyText, selectContents, type ClipboardWriter } from "./clipboard.ts";

export function initializeAgentSetups(documentValue: Document, navigatorValue: Navigator): void {
  for (const root of documentValue.querySelectorAll<HTMLElement>("[data-hraness-agent-setup-prompt]")) {
    if (root.dataset.enhanced === "true") continue;
    const details = root.querySelector<HTMLDetailsElement>(".hraness-agent-setup__details");
    const source = root.querySelector<HTMLElement>(".hraness-agent-setup__full");
    const preview = root.querySelector<HTMLElement>(".hraness-agent-setup__preview");
    const summary = details?.querySelector<HTMLElement>("summary");
    const frame = root.querySelector<HTMLElement>(".hraness-agent-setup__frame");
    const button = root.querySelector<HTMLButtonElement>(".hraness-agent-setup__copy");
    const label = button?.querySelector<HTMLElement>("span");
    const status = root.querySelector<HTMLElement>("[role=status]");
    if (!details || !source || !preview || !summary || !frame || !button || !label || !status) continue;
    const synchronize = () => {
      preview.hidden = details.open;
      summary.textContent = details.open ? "Hide full prompt" : "Show full prompt";
    };
    details.addEventListener("toggle", synchronize);
    const forced = documentValue.defaultView?.matchMedia?.("(forced-colors: active)");
    const disclose = () => { if (forced?.matches) { details.open = true; synchronize(); } };
    forced?.addEventListener("change", disclose);
    disclose();
    synchronize();
    let busy = false;
    let generation = 0;
    const pendingTabs = new Set<Window>();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const state = (value: "idle" | "copying" | "copied" | "failed", message = "") => {
      button.dataset.copyState = frame.dataset.copyState = value;
      button.disabled = value === "copying";
      if (value === "copying") button.setAttribute("aria-busy", "true");
      else button.removeAttribute("aria-busy");
      button.setAttribute("aria-label", `${value === "copied" ? "Copied" : "Copy"} setup prompt`);
      label.textContent = value === "copied" ? "Copied" : value === "copying" ? "Copying" : value === "failed" ? "Copy failed" : "Copy";
      status.textContent = message;
    };
    const copy = async (): Promise<boolean> => {
      if (busy) return false;
      const prompt = source.textContent ?? "";
      if (!prompt.trim()) return false;
      busy = true;
      const request = ++generation;
      if (timer !== undefined) clearTimeout(timer);
      state("copying", "Copying setup prompt.");
      let clipboard: ClipboardWriter | undefined;
      try { clipboard = navigatorValue.clipboard; } catch { clipboard = undefined; }
      let selected = false;
      const select = () => {
        details.open = true;
        synchronize();
        source.focus();
        selected = selectContents(source, documentValue);
        return selected;
      };
      const ok = await copyText(prompt, clipboard, () => request === generation && source.isConnected && source.textContent === prompt && legacyCopyText(prompt, documentValue));
      // Never hand off text that changed while clipboard permission was pending.
      if (request !== generation || source.textContent !== prompt || !source.isConnected) {
        if (request === generation) { busy = false; state("idle"); }
        return false;
      }
      busy = false;
      if (!ok && !selected) select();
      state(ok ? "copied" : "failed", ok ? "Copied setup prompt." : selected
        ? "Copy failed. The setup prompt is selected; copy it with your keyboard."
        : "Copy failed. Select the setup prompt and copy it with your keyboard.");
      timer = setTimeout(() => state("idle"), 2000);
      return ok;
    };
    documentValue.defaultView?.addEventListener("pagehide", () => {
      generation += 1;
      busy = false;
      if (timer !== undefined) clearTimeout(timer);
      for (const popup of pendingTabs) { try { popup.close(); } catch {} }
      pendingTabs.clear();
      state("idle");
    });
    button.addEventListener("click", () => { void copy(); });
    for (const target of root.querySelectorAll<HTMLAnchorElement>('[data-agent-target-mode="copy-and-open"]')) {
      target.addEventListener("click", (event) => {
        event.preventDefault();
        if (busy) return;
        const url = new URL(target.href);
        if (!["https:", "http:", "codex:"].includes(url.protocol) || url.username || url.password) return;
        const destination = url.href;
        void copyAndOpen(copy, () => {
          const popup = documentValue.defaultView?.open("about:blank", "_blank");
          if (!popup) return null;
          try {
            popup.opener = null;
            const policy = popup.document.createElement("meta");
            policy.name = "referrer";
            policy.content = "no-referrer";
            popup.document.head.append(policy);
          } catch {
            popup.close();
            return null;
          }
          pendingTabs.add(popup);
          return {
            close: () => { pendingTabs.delete(popup); popup.close(); },
            navigate: () => {
              if (popup.closed || !target.isConnected || target.href !== destination || !source.isConnected) return false;
              popup.location.replace(destination);
              pendingTabs.delete(popup);
              return true;
            },
          };
        }).then(({ copied, opened }) => {
          if (copied && !opened) status.textContent = `Prompt copied. Open ${target.textContent?.trim() || "the agent"} from the link's menu.`;
        });
      });
    }
    button.hidden = false;
    root.dataset.enhanced = "true";
  }
}
