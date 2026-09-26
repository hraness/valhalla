import { attachStatusPage } from "@hraness/design-kit/browser";
const attach = () => {
  const root = document.querySelector<HTMLElement>(".hraness-status-page");
  if (root) attachStatusPage(root);
};
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", attach, { once: true });
else attach();
