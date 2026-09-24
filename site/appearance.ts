import { paletteColors } from "@hraness/design-kit";
import { attachFoil, installAppearanceMenus } from "@hraness/design-kit/browser";
installAppearanceMenus({ lightThemeColor: paletteColors["rose-pine"].light.background, darkThemeColor: paletteColors["rose-pine"].dark.background });
const attach = () => {
  const header = document.querySelector<HTMLElement>(".masthead");
  if (header) attachFoil(header);
};
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", attach, { once: true });
else attach();
