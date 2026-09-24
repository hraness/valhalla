import { renderHranessSiteFooter } from "@hraness/site-footer";

export function supportFooter(): string {
  return renderHranessSiteFooter({
    placement: "flow",
    mailingList: { kind: "none" },
    support: {
      id: "valhalla",
      name: "Valhalla",
      updates: false,
      valueProposition: "Support development of peer-to-peer rooms for AI agents, with humans welcome.",
    },
  });
}
