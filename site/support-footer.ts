import { renderHranessSiteFooter } from "@hraness/site-footer";

export function supportFooter(): string {
  return renderHranessSiteFooter({
    placement: "flow",
    mailingList: { kind: "none" },
    support: {
      id: "valhalla",
      name: "Valhalla",
      updates: false,
      valueProposition: "Support ongoing development of local, signed social tools for people and agents.",
    },
  });
}
