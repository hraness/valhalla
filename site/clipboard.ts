export type ClipboardWriter = Readonly<{ writeText: (value: string) => Promise<void> }>;

export async function copyText(value: string, clipboard: ClipboardWriter | undefined, fallback: () => boolean): Promise<boolean> {
  if (clipboard !== undefined) {
    try {
      await clipboard.writeText(value);
      return true;
    } catch {
      // A denied or unavailable clipboard leaves the complete source selectable.
    }
  }
  try { return fallback(); }
  catch { return false; }
}

/** Native fallback keeps rendered-selection whitespace and textarea normalization out of copied bytes. */
export function legacyCopyText(value: string, documentValue: Document): boolean {
  const previous = documentValue.activeElement as HTMLElement | null;
  let buffer: HTMLTextAreaElement | undefined;
  let copied = false;
  let exactEvent = false;
  const writeExact = (event: ClipboardEvent) => {
    if (documentValue.activeElement !== buffer || event.clipboardData === null) return;
    try {
      event.clipboardData.setData("text/plain", value);
      event.preventDefault();
      exactEvent = event.defaultPrevented;
    } catch { /* A denied event leaves the native fallback or manual copy available. */ }
  };
  try {
    buffer = documentValue.createElement("textarea");
    buffer.value = value;
    buffer.readOnly = true;
    buffer.tabIndex = -1;
    buffer.dataset.clipboardFallback = "true";
    buffer.style.cssText = "position:fixed;top:0;left:0;width:1px;height:1px;opacity:0;overflow:hidden;resize:none";
    documentValue.body.append(buffer);
    buffer.focus({ preventScroll: true });
    buffer.select();
    buffer.setSelectionRange(0, value.length);
    documentValue.addEventListener("copy", writeExact);
    copied = documentValue.execCommand("copy") === true && (buffer.value === value || exactEvent);
    return copied;
  } catch { return false; }
  finally {
    documentValue.removeEventListener("copy", writeExact);
    buffer?.remove();
    if (copied && previous?.isConnected && typeof previous.focus === "function") {
      try { previous.focus({ preventScroll: true }); } catch { /* The prior control may have disappeared. */ }
    }
  }
}

export function selectContents(element: HTMLElement, documentValue: Document): boolean {
  try {
    const selection = documentValue.getSelection();
    if (selection === null) return false;
    const range = documentValue.createRange();
    range.selectNodeContents(element);
    selection.removeAllRanges();
    selection.addRange(range);
    return true;
  } catch { return false; }
}

export type ReservedProviderWindow = Readonly<{ navigate: () => boolean; close: () => void }>;

/** Start copying in the source document, then reserve a tab in the same gesture. */
export async function copyAndOpen(copy: () => Promise<boolean>, reserve: () => ReservedProviderWindow | null): Promise<Readonly<{ copied: boolean; opened: boolean }>> {
  const pending = copy();
  let owned: ReservedProviderWindow | null = null;
  try { owned = reserve(); } catch { /* A blocked reservation must not stop copying. */ }
  const close = () => { try { owned?.close(); } catch { /* The owned tab may already be closed. */ } };
  let copied = false;
  try { copied = await pending; } catch { /* A failed copy must never navigate. */ }
  if (!copied) { close(); return { copied: false, opened: false }; }
  let opened = false;
  try { opened = owned?.navigate() === true; } catch { /* Keep the native link available. */ }
  if (!opened) close();
  return { copied: true, opened };
}
