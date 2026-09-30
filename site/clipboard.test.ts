import { expect, test } from "bun:test";
import { copyAndOpen, copyText, legacyCopyText } from "./clipboard.ts";

test("copy preserves every source byte, including whitespace and trust placeholders", async () => {
  const prompt = "Pin this network:\n  vhalla public bootstrap-check BOOTSTRAP PIN64\n\nCheck its full fingerprint.\n";
  const written: string[] = [];
  let fallback = 0;
  expect(await copyText(prompt, { writeText: async value => { written.push(value); } }, () => { fallback += 1; return false; })).toBe(true);
  expect(written).toEqual([prompt]);
  expect(fallback).toBe(0);
});

test("denied and unavailable clipboards use the caller's selection fallback", async () => {
  let fallback = 0;
  expect(await copyText("whole source", { writeText: async () => { throw new Error("denied"); } }, () => { fallback += 1; return true; })).toBe(true);
  expect(await copyText("whole source", undefined, () => { fallback += 1; return false; })).toBe(false);
  expect(await copyText("whole source", undefined, () => { throw new Error("selection unavailable"); })).toBe(false);
  expect(fallback).toBe(2);
});

function legacyFixture(result: boolean | Error, emitCopy: boolean) {
  const written: string[] = [];
  const children: object[] = [];
  const listeners = new Set<(event: ClipboardEvent) => void>();
  let restored = 0;
  const previous = { isConnected: true, focus: () => { restored += 1; } };
  const documentValue = {
    activeElement: previous as object,
    body: { append: (node: object) => { children.push(node); } },
    createElement: (name: string) => { expect(name).toBe("textarea"); return buffer; },
    addEventListener: (name: string, callback: (event: ClipboardEvent) => void) => { expect(name).toBe("copy"); listeners.add(callback); },
    removeEventListener: (name: string, callback: (event: ClipboardEvent) => void) => { expect(name).toBe("copy"); listeners.delete(callback); },
    execCommand: (name: string) => {
      expect(name).toBe("copy");
      expect(documentValue.activeElement).toBe(buffer);
      expect(buffer.readOnly).toBe(true);
      expect(buffer.tabIndex).toBe(-1);
      expect(buffer.selected).toBe(true);
      if (result instanceof Error) throw result;
      if (emitCopy) {
        const event = { defaultPrevented: false,
          clipboardData: { setData: (type: string, value: string) => { expect(type).toBe("text/plain"); written.push(value); } },
          preventDefault: () => { event.defaultPrevented = true; } };
        for (const listener of listeners) listener(event as unknown as ClipboardEvent);
      }
      return result;
    },
  };
  let normalized = "";
  const buffer = {
    get value() { return normalized; },
    set value(value: string) { normalized = value.replace(/\r\n?/gu, "\n"); },
    readOnly: false, tabIndex: 0, dataset: {} as Record<string, string>, style: { cssText: "" }, selected: false,
    focus: (options: { preventScroll: boolean }) => { expect(options.preventScroll).toBe(true); documentValue.activeElement = buffer; },
    select: () => { buffer.selected = true; },
    setSelectionRange: (start: number, end: number) => { expect(start).toBe(0); expect(end).toBeGreaterThanOrEqual(buffer.value.length); },
    remove: () => { children.splice(children.indexOf(buffer), 1); },
  };
  return { documentValue: documentValue as unknown as Document, written, children, listeners, restored: () => restored };
}

test("native fallback retains trailing whitespace and original CRLF/CR bytes and cleans up before restoring focus", () => {
  for (const text of ["  full prompt\n\n", "full\r\nsource\r\n", "full\rsource\r"]) {
    const fixture = legacyFixture(true, true);
    expect(legacyCopyText(text, fixture.documentValue)).toBe(true);
    expect(fixture.written).toEqual([text]);
    expect(fixture.children).toHaveLength(0);
    expect(fixture.listeners.size).toBe(0);
    expect(fixture.restored()).toBe(1);
  }
});

test("native fallback accepts exact values and rejects denial, exceptions, and unqualified newline normalization", () => {
  for (const [result, text, expected] of [
    [true, "full source\n", true], [false, "full source\n", false],
    [new Error("denied"), "full source\n", false], [true, "full\r\nsource\r", false],
  ] as const) {
    const fixture = legacyFixture(result, false);
    expect(legacyCopyText(text, fixture.documentValue)).toBe(expected);
    expect(fixture.children).toHaveLength(0);
    expect(fixture.listeners.size).toBe(0);
    expect(fixture.restored()).toBe(expected ? 1 : 0);
  }
});

test("copy starts before tab reservation and provider navigation waits for completion", async () => {
  let finish: (ok: boolean) => void = () => {};
  const events: string[] = [];
  const pending = copyAndOpen(() => {
    events.push("copy");
    return new Promise<boolean>(resolve => { finish = resolve; });
  }, () => {
    events.push("reserve");
    return { navigate: () => { events.push("navigate"); return true; }, close: () => { events.push("close"); } };
  });
  expect(events).toEqual(["copy", "reserve"]);
  finish(true);
  expect(await pending).toEqual({ copied: true, opened: true });
  expect(events).toEqual(["copy", "reserve", "navigate"]);
});

test("denied or stale copying closes the reserved tab without provider navigation", async () => {
  for (const copy of [async () => false, async () => { throw new Error("stale source"); }]) {
    const events: string[] = [];
    const result = await copyAndOpen(copy, () => ({
      navigate: () => { events.push("navigate"); return true; },
      close: () => { events.push("close"); },
    }));
    expect(result).toEqual({ copied: false, opened: false });
    expect(events).toEqual(["close"]);
  }
});

test("blocked reservations still copy, while refused navigation closes the owned blank tab", async () => {
  expect(await copyAndOpen(async () => true, () => null)).toEqual({ copied: true, opened: false });
  expect(await copyAndOpen(async () => true, () => { throw new Error("blocked"); })).toEqual({ copied: true, opened: false });
  let closed = 0;
  expect(await copyAndOpen(async () => true, () => ({ navigate: () => false, close: () => { closed += 1; } }))).toEqual({ copied: true, opened: false });
  expect(closed).toBe(1);
});
