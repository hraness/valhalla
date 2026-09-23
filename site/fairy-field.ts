/* The fairy field's interaction layer. The DOM ships in index.html; this
 * script sets --prox on every light, sign, and tower by pointer distance,
 * and --wave for the expanding reveal ring a press sends through the wall.
 * --breath/--bloomv run in CSS — twinkle and drift need no timers here.
 * Everything is decorative: the field is aria-hidden and pointer-transparent,
 * and prefers-reduced-motion leaves the still collage untouched. */

const REVEAL_RADIUS = 340;
const WAVE_SPEED = 560;   // px/s — the ring's expanding front
const WAVE_BAND = 150;    // px — how wide the lit band stays
const WAVE_SECONDS = 1.8; // total wave lifetime
const MAX_WAVES = 4;

const root = document.querySelector<HTMLElement>(".fairy-field");
if (root !== null && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
  const targets = Array.from(root.querySelectorAll<HTMLElement>("[data-prox]"));
  if (targets.length > 0) {
    const centers = new Map<HTMLElement, readonly [number, number]>();
    const measure = () => {
      centers.clear();
      for (const el of targets) {
        const rect = el.getBoundingClientRect();
        centers.set(el, [rect.left + rect.width / 2, rect.top + rect.height / 2]);
      }
    };
    measure();

    const waves: { x: number; y: number; t0: number }[] = [];
    let raf = 0;
    let waveRaf = 0;
    let pointerX = -10000;
    let pointerY = -10000;

    const apply = () => {
      raf = 0;
      for (const el of targets) {
        const center = centers.get(el);
        if (center === undefined) continue;
        const distance = Math.hypot(center[0] - pointerX, center[1] - pointerY);
        const proximity = Math.max(0, 1 - distance / REVEAL_RADIUS);
        el.style.setProperty("--prox", proximity.toFixed(3));
      }
    };
    const schedule = () => {
      if (raf === 0) raf = requestAnimationFrame(apply);
    };
    const onMove = (event: PointerEvent) => {
      pointerX = event.clientX;
      pointerY = event.clientY;
      schedule();
    };
    const onAway = () => {
      pointerX = -10000;
      pointerY = -10000;
      schedule();
    };

    /* A press plants an expanding ring: each light flares as the front
     * passes it, then settles as the ring moves on. --wave fades with age. */
    const applyWaves = (now: number) => {
      waveRaf = 0;
      let alive = false;
      for (const el of targets) {
        const center = centers.get(el);
        let strongest = 0;
        if (center !== undefined) {
          for (const wave of waves) {
            const elapsed = (now - wave.t0) / 1000;
            if (elapsed > WAVE_SECONDS) continue;
            alive = true;
            const front = elapsed * WAVE_SPEED;
            const distance = Math.abs(Math.hypot(center[0] - wave.x, center[1] - wave.y) - front);
            const band = Math.max(0, 1 - distance / WAVE_BAND);
            const strength = band * Math.max(0, 1 - elapsed / WAVE_SECONDS);
            if (strength > strongest) strongest = strength;
          }
        }
        el.style.setProperty("--wave", strongest.toFixed(3));
      }
      for (let index = waves.length - 1; index >= 0; index -= 1) {
        if ((now - waves[index].t0) / 1000 > WAVE_SECONDS) waves.splice(index, 1);
      }
      if (alive) waveRaf = requestAnimationFrame(applyWaves);
    };
    const onPointerDown = (event: PointerEvent) => {
      if (centers.size === 0) return;
      if (waves.length >= MAX_WAVES) waves.shift();
      waves.push({ x: event.clientX, y: event.clientY, t0: performance.now() });
      if (waveRaf === 0) waveRaf = requestAnimationFrame(applyWaves);
    };

    window.addEventListener("pointermove", onMove, { passive: true });
    window.addEventListener("scroll", measure, { capture: true, passive: true });
    window.addEventListener("resize", measure);
    document.documentElement.addEventListener("pointerleave", onAway);
    window.addEventListener("blur", onAway);
    const wall = root.parentElement;
    wall?.addEventListener("pointerdown", onPointerDown, { passive: true });
  }
}

export {};
