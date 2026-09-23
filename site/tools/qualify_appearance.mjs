// Focused checks run against the same static server, real Chromium and CSP as
// qualify_browser.mjs. No synthetic page lifecycle events or mocked media APIs.
export async function qualifyAppearance({call, evaluate, navigate, sessionId}) {
  const key = 'hraness-design-theme-v1';
  const expected = {light: 'rgb(250, 244, 237)', dark: 'rgb(25, 23, 36)'};
  const state = () => evaluate(`({
    palette: document.documentElement.dataset.palette,
    theme: document.documentElement.dataset.theme,
    selected: document.querySelector('[data-theme-value][aria-checked="true"]')?.dataset.themeValue,
    stored: localStorage.getItem(${JSON.stringify(key)}),
    background: getComputedStyle(document.documentElement).backgroundColor,
    meta: [...document.querySelectorAll('meta[name="theme-color"]')].map(x => ({content:x.content,media:x.media}))
  })`);
  const waitFor = async (predicate, label) => {
    for (let i = 0; i < 120; i++) {
      if (await predicate()) return;
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    throw Error('appearance qualification timed out: ' + label);
  };
  const media = (value, extra = []) => call('Emulation.setEmulatedMedia', {
    features: [{name:'prefers-color-scheme',value}, ...extra],
  }, sessionId);
  const assertState = async (theme, selected, stored) => {
    await waitFor(async () => {
      const s = await state();
      return s.theme === theme && s.selected === selected && s.background === expected[theme];
    }, theme + '/' + selected);
    const s = await state();
    if (s.palette !== 'rose-pine' || s.stored !== stored) throw Error(JSON.stringify(s));
    const color = theme === 'dark' ? '#191724' : '#faf4ed';
    if (!s.meta.some(m => m.content === color && (!m.media || matchScheme(m.media,theme)))) {
      throw Error('theme-color does not match active palette: ' + JSON.stringify(s));
    }
    return s;
  };
  const choose = async mode => {
    await evaluate(`(() => {
      document.querySelector('[data-hraness-appearance-menu] button').click();
      document.querySelector('[data-theme-value="${mode}"]').click();
    })()`);
  };

  await call('Page.bringToFront',{},sessionId);
  await call('Emulation.setTouchEmulationEnabled',{enabled:false},sessionId);
  await media('dark');
  await navigate('/',1365,950);
  const desktopMedia = await evaluate("matchMedia('(hover: hover) and (pointer: fine) and (prefers-reduced-motion: no-preference) and (forced-colors: none)').matches");
  if (!desktopMedia) throw Error('Native desktop input configuration did not apply');
  const firstVisit = await assertState('dark','system',null);
  await media('light');
  const liveLight = await assertState('light','system',null);
  await media('dark');
  const liveDark = await assertState('dark','system',null);

  await choose('light');
  await assertState('light','light','light');
  await navigate('/docs/private-rooms/',1365,950);
  const savedLight = await assertState('light','light','light');
  await media('light');
  await choose('dark');
  await navigate('/',1365,950);
  const savedDark = await assertState('dark','dark','dark');
  await choose('system');
  await assertState('light','system','system');
  await media('dark');
  const restoredSystem = await assertState('dark','system','system');

  // Observe actual pagehide/pageshow delivery and keep the same document token.
  // A reload or a synthetic event cannot satisfy this BFcache assertion.
  const token = await evaluate(`(() => {
    window.__appearanceQualification = {token: crypto.randomUUID(), events: []};
    for (const name of ['pagehide','pageshow']) addEventListener(name, event => {
      const hero = document.querySelector('.introduction');
      window.__appearanceQualification.events.push({name,persisted:event.persisted,
        light:hero.style.getPropertyValue('--hraness-hero-light-x')});
    });
    return window.__appearanceQualification.token;
  })()`);
  const move = async fraction => {
    await call('Page.bringToFront',{},sessionId);
    await waitFor(() => evaluate("document.visibilityState === 'visible'"),'foreground desktop target');
    // Native media-query change events and their cleanup run asynchronously.
    // Settle them before sending the new input whose response is being tested.
    await evaluate('new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
    const point = await evaluate(`(() => {const b=document.querySelector('.introduction').getBoundingClientRect();
      return {x:b.left+b.width*${fraction},y:Math.max(1,b.top)+Math.min(b.height,innerHeight-Math.max(1,b.top))*0.3};})()`);
    await call('Input.dispatchMouseEvent',{type:'mouseMoved',...point},sessionId);
    try {
      await waitFor(() => evaluate("!!document.querySelector('.introduction').style.getPropertyValue('--hraness-hero-light-x')"),'trusted hero pointer input');
    } catch (cause) {
      const diagnostic = await evaluate(`({visibility:document.visibilityState,focused:document.hasFocus(),
        media:matchMedia('(hover: hover) and (pointer: fine) and (prefers-reduced-motion: no-preference) and (forced-colors: none)').matches,
        features:Object.fromEntries(['(hover: hover)','(hover: none)','(pointer: fine)','(pointer: coarse)',
          '(pointer: none)','(prefers-reduced-motion: no-preference)','(prefers-reduced-motion: reduce)',
          '(forced-colors: none)','(forced-colors: active)','(prefers-reduced-transparency: reduce)']
          .map(query=>[query,matchMedia(query).matches])),
        hit:document.elementFromPoint(${point.x},${point.y})?.tagName,
        inside:!!document.elementFromPoint(${point.x},${point.y})?.closest('.introduction')})`);
      throw Error('trusted hero pointer input: '+JSON.stringify(diagnostic),{cause});
    }
    return evaluate(`(() => {const s=document.querySelector('.introduction').style;
      return ['--hraness-hero-light-x','--hraness-hero-light-y','--hraness-hero-drift-x','--hraness-hero-drift-y'].map(n=>s.getPropertyValue(n));})()`);
  };
  const before = await move(0.3);
  const history = await call('Page.getNavigationHistory',{},sessionId);
  const homeEntry = history.entries[history.currentIndex].id;
  await navigate('/docs/private-rooms/',1365,950);
  await call('Page.navigateToHistoryEntry',{entryId:homeEntry},sessionId);
  await waitFor(() => evaluate(`location.pathname === '/' && window.__appearanceQualification?.token === ${JSON.stringify(token)} && window.__appearanceQualification.events.some(e=>e.name==='pageshow'&&e.persisted)`),'actual BFcache restore');
  const lifecycle = await evaluate('window.__appearanceQualification.events');
  if (!lifecycle.some(e=>e.name==='pagehide'&&e.persisted&&e.light==='')) {
    throw Error('hero pagehide did not restore owned CSS properties: '+JSON.stringify(lifecycle));
  }
  const after = await move(0.7);
  if (after.some(v=>!v) || before[0] === after[0]) throw Error('hero input did not resume after BFcache');
  await media('light');
  const afterBack = await assertState('light','system','system');
  const suppression = [];
  for (const condition of ['coarse','reduced','forced']) {
    if (condition === 'coarse') await call('Emulation.setTouchEmulationEnabled',{enabled:true,maxTouchPoints:1},sessionId);
    else await media('light',[condition==='reduced'
      ? {name:'prefers-reduced-motion',value:'reduce'} : {name:'forced-colors',value:'active'}]);
    const query = condition === 'coarse' ? '(pointer: coarse)' : condition === 'reduced'
      ? '(prefers-reduced-motion: reduce)' : '(forced-colors: active)';
    if (!await evaluate(`matchMedia(${JSON.stringify(query)}).matches`)) throw Error('Native negative condition missing: '+condition);
    await waitFor(() => evaluate("!document.querySelector('.introduction').style.getPropertyValue('--hraness-hero-light-x')"),condition+' resets hero input');
    await call('Input.dispatchMouseEvent',{type:'mouseMoved',x:240,y:240},sessionId);
    await evaluate('new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
    if (await evaluate("!!document.querySelector('.introduction').style.getPropertyValue('--hraness-hero-light-x')")) throw Error('Hero input ignored '+condition+' guard');
    suppression.push(condition);
    await call('Emulation.setTouchEmulationEnabled',{enabled:false},sessionId);
    await media('light');
    try { await move(0.7); }
    catch (cause) { throw Error('Hero did not resume after '+condition,{cause}); }
  }
  return {desktopMedia,suppression,firstVisit,liveLight,liveDark,savedLight,savedDark,restoredSystem,
    bfcache:{token,lifecycle,before,after,afterBack}};
}

function matchScheme(media, theme) {
  return media === `(prefers-color-scheme: ${theme})`;
}
