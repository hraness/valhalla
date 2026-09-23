import { attachHeroLight } from "@hraness/design-kit/browser";

// The authored fairy scene uses the shared bounded light controller. It owns
// only CSSOM properties; layout, pigments, and every decorative shape stay in CSS.
// No global pointer listener, idle animation loop, or touch interception.
const hero = document.querySelector<HTMLElement>(".introduction");
if (hero) {
  let dispose = attachHeroLight(hero);
  window.addEventListener("pagehide", () => dispose());
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) dispose = attachHeroLight(hero);
  });
}
