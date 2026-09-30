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
  return enhanced;
}
