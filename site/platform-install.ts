/*
 * Static rendering of the shared design-kit PlatformInstall and PlatformBadges
 * blocks. The kit's React components are StyleX-only, so this site renders the
 * same markup, hook class names and marks as plain HTML:
 * `platform-install-client.ts` adds the tabs, OS detection and Copy, and
 * `styles.css` carries the matching presentation. Without JavaScript every
 * platform's commands show in sequence.
 */
import { platformLabel, platformMark, type PlatformId } from "@hraness/design-kit";

export type StaticInstallAlternative = Readonly<{ label: string; command: string; shell?: string }>;

export type StaticPlatformInstallTarget = Readonly<{
  id: PlatformId;
  command: string;
  shell: string;
  note?: string;
  alternatives?: readonly StaticInstallAlternative[];
}>;

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

function icon(id: PlatformId): string {
  const mark = platformMark(id);
  return `<svg aria-hidden="true" class="hraness-platform-icon" fill="currentColor" focusable="false" viewBox="${mark.viewBox}"><path d="${mark.path}"></path></svg>`;
}

/** Each mark is defined once per block as a `<symbol>` and drawn by reference, like the kit. */
function symbols(ids: readonly PlatformId[], symbolId: (id: PlatformId) => string): string {
  const body = ids.map((id) => {
    const mark = platformMark(id);
    return `<symbol id="${symbolId(id)}" viewBox="${mark.viewBox}"><path d="${mark.path}"></path></symbol>`;
  }).join("");
  return `<svg aria-hidden="true" class="hraness-platform-install__marks" focusable="false" xmlns="http://www.w3.org/2000/svg">${body}</svg>`;
}

function markUse(id: PlatformId, symbolId: string): string {
  return `<svg aria-hidden="true" class="hraness-platform-icon" data-platform="${id}" fill="currentColor" focusable="false" viewBox="${platformMark(id).viewBox}"><use href="#${symbolId}"></use></svg>`;
}

const copyGlyph = '<svg aria-hidden="true" class="hraness-platform-install__copy-icon" fill="none" focusable="false" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" viewBox="0 0 24 24"><rect height="12" rx="2" width="12" x="8" y="8"></rect><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"></path></svg>';

function commandBlock(caption: string, command: string, subject: string): string {
  return `<div class="hraness-platform-install__command" data-copy-state="idle"><div class="hraness-platform-install__command-bar"><span class="hraness-platform-install__shell">${escapeHtml(caption)}</span><button class="hraness-platform-install__copy" data-copy-state="idle" data-platform-install-copy hidden type="button">${copyGlyph}<span data-platform-install-copy-label>Copy</span><span class="hraness-platform-install__status"> ${escapeHtml(subject)}</span></button></div><pre aria-label="${escapeHtml(subject)}" class="hraness-platform-install__pre" tabindex="0"><code class="hraness-platform-install__code">${escapeHtml(command)}</code></pre></div>`;
}

export function renderPlatformInstall(id: string, platforms: readonly StaticPlatformInstallTarget[], label = "Platform"): string {
  const [first] = platforms;
  if (first === undefined) throw new RangeError("Platform install needs at least one platform.");
  const seen = new Set<string>();
  for (const target of platforms) {
    if (seen.has(target.id)) throw new RangeError(`Duplicate platform id: ${target.id}.`);
    seen.add(target.id);
    if (!target.command.trim()) throw new RangeError(`Platform ${target.id} needs a command.`);
  }
  const symbolId = (platform: PlatformId) => `${id}-mark-${platform}`;
  const tabs = platforms.map((target) => {
    const selected = target.id === first.id;
    return `<button aria-controls="${id}-panel-${target.id}" aria-selected="${selected}" class="hraness-platform-install__tab" data-availability="available" data-platform="${target.id}" id="${id}-tab-${target.id}" role="tab" tabindex="${selected ? 0 : -1}" type="button">${markUse(target.id, symbolId(target.id))}<span class="hraness-platform-install__tab-label">${escapeHtml(platformLabel(target.id))}</span></button>`;
  }).join("");
  const panels = platforms.map((target) => {
    const name = platformLabel(target.id);
    const alternatives = target.alternatives ?? [];
    const others = alternatives.length === 0 ? "" : `<ul aria-label="Other ways to install on ${escapeHtml(name)}" class="hraness-platform-install__alternatives">${alternatives.map((alternative) => `<li>${commandBlock([alternative.label, alternative.shell].filter(Boolean).join(" · "), alternative.command, `${name} ${alternative.label} command`)}</li>`).join("")}</ul>`;
    const note = target.note === undefined ? "" : `<div class="hraness-platform-install__note">${escapeHtml(target.note)}</div>`;
    return `<div aria-labelledby="${id}-tab-${target.id}" class="hraness-platform-install__panel" data-availability="available" data-platform="${target.id}" id="${id}-panel-${target.id}" role="tabpanel"><div class="hraness-platform-install__panel-body"><p class="hraness-platform-install__panel-label">${markUse(target.id, symbolId(target.id))}<span>${escapeHtml(name)}</span></p>${commandBlock(target.shell, target.command, `${name} install command`)}${others}${note}</div></div>`;
  }).join("");
  return `<div class="hraness-platform-install" data-hraness-platform-install="" data-selected-platform="${first.id}" data-selection-source="default" id="${id}">${symbols(platforms.map((target) => target.id), symbolId)}<div aria-label="${escapeHtml(label)}" class="hraness-platform-install__tabs" hidden role="tablist">${tabs}</div>${panels}<p aria-live="polite" class="hraness-platform-install__status" role="status"></p></div>`;
}

export function renderPlatformBadges(platforms: readonly (PlatformId | Readonly<{ id: PlatformId; note: string }>)[], label = "Runs on"): string {
  const items = platforms.map((entry) => {
    const id = typeof entry === "string" ? entry : entry.id;
    const note = typeof entry === "string" ? "" : ` <span class="hraness-platform-badges__note">${escapeHtml(entry.note)}</span>`;
    return `<li class="hraness-platform-badges__item">${icon(id)}<span>${escapeHtml(platformLabel(id))}</span>${note}</li>`;
  }).join("");
  return `<div class="hraness-platform-badges"><span class="hraness-platform-badges__label">${escapeHtml(label)}</span><ul class="hraness-platform-badges__list">${items}</ul></div>`;
}

// vhalla's install commands. install.sh serves Apple silicon macOS and x86-64
// and ARM64 Linux; install.ps1 serves x86-64 Windows, where vhalla has help,
// identity and the member side of private rooms.
const unixInstall = "curl -fsSL https://vhalla.com/install.sh | sh";
const homebrew: StaticInstallAlternative = { label: "Homebrew", command: "brew install hraness/tap/vhalla", shell: "Terminal" };

export const vhallaPlatforms: readonly StaticPlatformInstallTarget[] = [
  { id: "macos", command: unixInstall, shell: "Terminal", note: "Apple silicon", alternatives: [homebrew] },
  { id: "linux", command: unixInstall, shell: "Terminal", note: "x86_64 and ARM64", alternatives: [homebrew] },
  { id: "windows", command: "irm https://vhalla.com/install.ps1 | iex", shell: "PowerShell", note: "x86_64 · help, identity and joining private rooms; hosting and the rest run in WSL2" },
];

export const vhallaRunsOn = ["macos", "linux", { id: "windows", note: "partial" }] as const;

export function vhallaInstall(id: string): string {
  return renderPlatformInstall(id, vhallaPlatforms);
}

export function vhallaBadges(): string {
  return renderPlatformBadges(vhallaRunsOn);
}
