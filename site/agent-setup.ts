import { agentSetupTargets } from "@hraness/design-kit";
import { AgentSetupPrompt } from "@hraness/design-kit/react";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

export { vhallaBootstrapPrompt, vhallaInstallPrompt } from "./agent-setup-prompts.ts";

export function renderAgentSetup(id: string, prompt: string, label: string): string {
  if (!/^[a-z][a-z0-9-]*$/u.test(id)) throw new RangeError("Static agent setup needs a unique HTML prefix.");
  const html = renderToStaticMarkup(createElement(AgentSetupPrompt, {
    label,
    prompt,
    targets: agentSetupTargets(prompt),
  }), { identifierPrefix: `${id}-` });
  let copies = 0;
  const enhanced = html.replace(/<button\b[^>]*>/gu, (tag) => {
    if (!/\bhraness-agent-setup__copy(?:\s|")/u.test(tag)) return tag;
    copies += 1;
    return tag.slice(0, -1) + " hidden>";
  });
  if (copies !== 1) throw new Error("The shared setup copy hook changed; update its static enhancement.");
  // The shared inherited marks need only their fixed size. Bind that value
  // in the external stylesheet so the site's strict CSP can keep it usable.
  const externalStyles = enhanced.replace(/<span\b[^>]*>/gu, (tag) => {
    const style = tag.match(/\sstyle="([^"]*)"/u);
    if (!style) return tag;
    if (!/\bhraness-provider-mark__inherit(?:\s|")/u.test(tag)
      || !/^--_mark-accent:#[\da-f]{6};--_mark-size:20px$/iu.test(style[1]!)) {
      throw new Error("The shared setup mark style changed; update its external CSS binding.");
    }
    return tag.replace(style[0], "");
  });
  if (/\sstyle=/u.test(externalStyles)) throw new Error("Static agent setup must use external styles.");
  return externalStyles;
}
