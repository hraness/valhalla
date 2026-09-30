import snapshot from "../portfolio-messaging.generated.json";
export const marketing = snapshot.messaging;
// Copy is authored in hraness/jungle; this renderer uses its checked snapshot offline.
export function renderPortfolioCopy(source: string, snapshot: { canonicalUrl?: string; messaging: { names: { name: string }; category: string; tagline: string; short: string; meta: string; hero: { heading: string; summary: string; primaryAction?: string; secondaryAction?: string }; headings: Readonly<Record<string, string>> } }): string {
  const copy = snapshot.messaging;
  const words = copy.hero.heading.split(" ");
  const fields: Readonly<Record<string, string | undefined>> = {
    NAME: copy.names.name, TITLE: `${copy.names.name} · ${copy.tagline}`, SOCIAL_ALT: `${copy.names.name}: ${copy.short}`,
    META: copy.meta, SHORT: copy.short, TAGLINE: copy.tagline, CATEGORY: copy.category,
    NAME_LOWER: copy.names.name.toLowerCase(),
    HERO_HEADING: copy.hero.heading, HERO_SUMMARY: copy.hero.summary,
    HERO_START: words.slice(0, -3).join(" "), HERO_END: words.slice(-3).join(" "),
    PRIMARY_ACTION: copy.hero.primaryAction, SECONDARY_ACTION: copy.hero.secondaryAction,
  };
  const escaped = (text: string) => text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
  // JSON-LD is serialized as JSON, independently from HTML text escaping.
  source = source.replace(/(<script[^>]*type=["']application\/ld\+json["'][^>]*>)([\s\S]*?)(<\/script>)/gu, (all, opening: string, body: string, closing: string) => {
    if (body.includes("{{")) return all;
    let changed = false;
    const update = (value: unknown): unknown => {
      if (Array.isArray(value)) return value.map(update);
      if (value === null || typeof value !== "object") return value;
      const record = Object.fromEntries(Object.entries(value).map(([key, child]) => [key, update(child)]));
      const ownsUrl = typeof record.url === "string" && record.url.replace(/\/$/u, "") === snapshot.canonicalUrl?.replace(/\/$/u, "");
      if ((record["@type"] === "WebSite" || record["@type"] === "SoftwareApplication") && (ownsUrl || record.name === copy.names.name) && (record.name !== copy.names.name || record.description !== copy.meta)) {
        record.name = copy.names.name;
        record.description = copy.meta;
        changed = true;
      }
      return record;
    };
    const updated = update(JSON.parse(body));
    if (!changed) return all;
    const leading = body.match(/^\s*/u)?.[0] ?? "";
    const trailing = body.match(/\s*$/u)?.[0] ?? "";
    const encoded = JSON.stringify(updated, null, body.includes("\n") ? 2 : undefined).replaceAll("<", "\\u003c");
    return opening + leading + encoded + trailing + closing;
  });
  return source.replace(/\{\{PORTFOLIO_([A-Z_]+)(?::([a-z0-9-]+))?\}\}/gu, (_all, field: string, key: string | undefined) => {
    const accentWords = key !== undefined && /^[1-9][0-9]?$/u.test(key) ? Number(key) : 3;
    const value = field === "HEADING" && key !== undefined ? copy.headings[key]
      : field === "HERO_START" ? words.slice(0, -accentWords).join(" ")
      : field === "HERO_END" ? words.slice(-accentWords).join(" ")
      : fields[field];
    if (value === undefined) throw new Error(`Missing canonical marketing copy: ${field}:${key ?? ""}`);
    return escaped(value);
  });
}

export const renderMarketingCopy = (source: string) => renderPortfolioCopy(source, snapshot);
