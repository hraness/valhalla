import assert from 'node:assert/strict';
import {agentSetupTargets} from '@hraness/design-kit';
import {vhallaDaemonPrompt, vhallaInstallPrompt} from '../agent-setup-prompts.ts';
import {javascriptLiteral} from './javascript-literal.mjs';

const prompts = [vhallaDaemonPrompt, vhallaInstallPrompt];
const selector = '[data-hraness-agent-setup-prompt]';

// This function runs in the real page, using its compiled stylesheet and palette.
function inspect(expected) {
  const canvas = document.createElement('canvas');
  canvas.width = canvas.height = 1;
  const context = canvas.getContext('2d', {willReadFrequently: true});
  const pixel = value => {
    context.clearRect(0, 0, 1, 1);
    context.fillStyle = value;
    context.fillRect(0, 0, 1, 1);
    return [...context.getImageData(0, 0, 1, 1).data];
  };
  const luminance = channels => channels.slice(0, 3).map(channel => {
    const value = channel / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  }).reduce((total, value, index) => total + value * [0.2126, 0.7152, 0.0722][index], 0);
  const ratio = (ink, surface) => {
    const a = pixel(ink), b = pixel(surface);
    if (a[3] !== 255 || b[3] !== 255) return 0;
    const left = luminance(a), right = luminance(b);
    return (Math.max(left, right) + 0.05) / (Math.min(left, right) + 0.05);
  };
  const roots = [...document.querySelectorAll('[data-hraness-agent-setup-prompt]')];
  return {
    width: innerWidth,
    overflow: document.documentElement.scrollWidth,
    theme: document.documentElement.dataset.theme,
    blocks: roots.map((root, index) => {
      const frame = root.querySelector('.hraness-agent-setup__frame');
      const source = root.querySelector('.hraness-agent-setup__full');
      const details = root.querySelector('details');
      const button = root.querySelector('.hraness-agent-setup__copy');
      const surface = getComputedStyle(frame).backgroundColor;
      return {
        enhanced: root.dataset.enhanced === 'true',
        completeSource: source.textContent === expected[index].prompt,
        disclosure: !!details.querySelector('summary') && source.tabIndex === 0,
        copyVisible: !button.hidden && button.getClientRects().length > 0,
        sourceContrast: ratio(getComputedStyle(source).color, surface),
        summaryContrast: ratio(getComputedStyle(details.querySelector('summary')).color, surface),
        controls: [...root.querySelectorAll('button, [data-agent-target]')].map(control => {
          const style = getComputedStyle(control), box = control.getBoundingClientRect();
          const glyph = control.querySelector('svg');
          const target = expected[index].targets.find(target => target.id === control.dataset.agentTarget);
          return {
            id: control.dataset.agentTarget ?? 'copy',
            width: box.width,
            height: box.height,
            contrast: ratio(style.color, style.backgroundColor),
            glyphInheritsInk: !glyph || getComputedStyle(glyph).color === style.color,
            destination: !target || (control.getAttribute('href') === target.href && control.dataset.agentTargetMode === target.mode),
            safeTarget: !target || (control.target === '_blank' && control.relList.contains('noopener') && control.relList.contains('noreferrer')),
          };
        }),
      };
    }),
  };
}

export async function qualifyAgentSetups({call, evaluate, navigate, sessionId}) {
  const expected = prompts.map(prompt => ({prompt, targets: agentSetupTargets(prompt)}));
  const waitFor = async (condition, label) => {
    for (let attempt = 0; attempt < 100; attempt++) {
      if (await condition()) return;
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    throw new Error('Agent setup qualification timed out: ' + label);
  };
  const results = [];
  for (const theme of ['light', 'dark']) for (const width of [390, 1440]) {
    await call('Emulation.setEmulatedMedia', {features: [{name: 'prefers-color-scheme', value: theme}, {name: 'forced-colors', value: 'none'}]}, sessionId);
    await navigate('/docs/agent-setup/', width, 900);
    const state = await evaluate('(' + inspect.toString() + ')(' + javascriptLiteral(expected) + ')');
    assert.equal(state.width, width);
    assert.ok(state.overflow <= width, 'Setup prompts must not overflow the viewport.');
    assert.equal(state.theme, theme);
    assert.equal(state.blocks.length, 2);
    for (const block of state.blocks) {
      assert.ok(block.enhanced && block.completeSource && block.disclosure && block.copyVisible, 'Shared prompt markup must be enhanced without losing its complete source.');
      assert.ok(block.sourceContrast >= 4.5 && block.summaryContrast >= 4.5, 'Prompt and disclosure text must have 4.5:1 contrast.');
      assert.equal(block.controls.length, expected[0].targets.length + 1);
      for (const control of block.controls) {
        assert.ok(control.width >= 44 && control.height >= 44, 'Setup controls must remain usable touch targets.');
        assert.ok(control.contrast >= 4.5 && control.glyphInheritsInk, 'Text and glyphs must use the shared readable foreground.');
        assert.ok(control.destination && control.safeTarget, 'Provider links must retain their full-source destinations and safe targets.');
      }
    }
    results.push({theme, width, ...state});
  }

  // Capture clipboard writes and owned blank-tab navigation only. No provider
  // app is opened and no host clipboard or signed-in browser is read or changed.
  await evaluate(`(() => {
    const state = window.__agentSetupQualification = {written: [], legacy: [], tabs: [], mode: 'success', finish: null,
      clipboard: Object.getOwnPropertyDescriptor(navigator, 'clipboard'),
      exec: Object.getOwnPropertyDescriptor(document, 'execCommand'), open: window.open};
    Object.defineProperty(navigator, 'clipboard', {configurable: true, value: {writeText: value => {
      state.written.push(value);
      if (state.mode === 'denied' || state.mode === 'legacy') return Promise.reject(Error('test clipboard denied'));
      if (state.mode === 'pending') return new Promise(resolve => {state.finish = resolve;});
      return Promise.resolve();
    }}});
    Object.defineProperty(document, 'execCommand', {configurable: true, value: () => {
      if (state.mode !== 'legacy') return false;
      const buffer = document.activeElement;
      const event = new ClipboardEvent('copy', {clipboardData: new DataTransfer(), bubbles: true, cancelable: true});
      document.dispatchEvent(event);
      state.legacy.push({value: buffer.value, copied: event.clipboardData.getData('text/plain'),
        readOnly: buffer.readOnly, tabIndex: buffer.tabIndex, hidden: buffer.hasAttribute('aria-hidden'),
        selectionStart: buffer.selectionStart, selectionEnd: buffer.selectionEnd});
      return true;
    }});
    window.open = (url, target) => {
      if (state.mode === 'blocked') return null;
      const tab = {url, target, closed: false, opener: window, document: document.implementation.createHTMLDocument(''),
        location: {replace: href => {tab.destination = href;}}, close: () => {tab.closed = true;}};
      state.tabs.push(tab);
      return tab;
    };
  })()`);
  try {
    for (const [index, prompt] of prompts.entries()) {
      const root = `document.querySelectorAll(${javascriptLiteral(selector)})[${index}]`;
      await evaluate(`(() => {window.__agentSetupQualification.mode = 'success';${root}.querySelector('button').click();})()`);
      await waitFor(() => evaluate(`${root}.querySelector('button').dataset.copyState === 'copied'`), 'complete-source clipboard copy');
      assert.equal(await evaluate('window.__agentSetupQualification.written.at(-1)'), prompt);

      await evaluate(`(() => {window.__agentSetupQualification.mode = 'legacy';const button=${root}.querySelector('button');button.focus();button.click();})()`);
      await waitFor(() => evaluate(`${root}.querySelector('button').dataset.copyState === 'copied'`), 'exact-value legacy clipboard fallback');
      assert.deepEqual(await evaluate('window.__agentSetupQualification.legacy.at(-1)'), {
        value: prompt, copied: prompt, readOnly: true, tabIndex: -1, hidden: false, selectionStart: 0, selectionEnd: prompt.length,
      });
      assert.ok(await evaluate(`document.activeElement === ${root}.querySelector('button') && document.querySelector('[data-clipboard-fallback]') === null`), 'Legacy copying must remove its temporary field and restore the source control’s focus.');
      await evaluate(`${root}.querySelector('[data-agent-target-mode="copy-and-open"]').click()`);
      await waitFor(() => evaluate('!!window.__agentSetupQualification.tabs.at(-1).destination'), 'legacy copy before provider handoff');
      assert.equal(await evaluate('window.__agentSetupQualification.legacy.at(-1).copied'), prompt);
      assert.equal(await evaluate('document.querySelector("[data-clipboard-fallback]")'), null);
      const before = await evaluate('window.__agentSetupQualification.tabs.length');
      await evaluate(`(() => {window.__agentSetupQualification.mode = 'pending';const link = ${root}.querySelector('[data-agent-target-mode="copy-and-open"]');link.click();link.click();})()`);
      const pending = await evaluate(`(() => {const s=window.__agentSetupQualification,t=s.tabs.at(-1);return {count:s.tabs.length,url:t.url,target:t.target,opener:t.opener,policy:t.document.querySelector('meta[name=referrer]')?.content,destination:t.destination??null};})()`);
      assert.equal(pending.count, before + 1, 'Pending repeats must reserve only one tab.');
      assert.equal(pending.url, 'about:blank');
      assert.equal(pending.target, '_blank');
      assert.equal(pending.opener, null);
      assert.equal(pending.policy, 'no-referrer');
      assert.equal(pending.destination, null, 'A pending copy must not navigate to a provider.');
      await evaluate('window.__agentSetupQualification.finish()');
      await waitFor(() => evaluate('!!window.__agentSetupQualification.tabs.at(-1).destination'), 'successful provider handoff');
      assert.equal(await evaluate('window.__agentSetupQualification.written.at(-1)'), prompt);
      const destination = await evaluate(`${root}.querySelector('[data-agent-target-mode="copy-and-open"]').href`);
      assert.equal(await evaluate('window.__agentSetupQualification.tabs.at(-1).destination'), destination);

      await evaluate(`(() => {window.__agentSetupQualification.mode = 'denied';${root}.querySelector('[data-agent-target-mode="copy-and-open"]').click();})()`);
      await waitFor(() => evaluate('window.__agentSetupQualification.tabs.at(-1).closed'), 'denied copy closes its reserved tab');
      assert.equal(await evaluate('window.__agentSetupQualification.tabs.at(-1).destination ?? null'), null);
      assert.equal(await evaluate('getSelection()?.rangeCount ? getSelection().getRangeAt(0).cloneContents().textContent : null'), prompt, 'Denied copying must expose and select the complete prompt source.');
      assert.ok(await evaluate(`${root}.querySelector('details').open && ${root}.querySelector('.hraness-agent-setup__preview').hidden`));

      await evaluate(`(() => {window.__agentSetupQualification.mode = 'pending';${root}.querySelector('[data-agent-target-mode="copy-and-open"]').click();${root}.querySelector('.hraness-agent-setup__full').textContent='changed during copying';window.__agentSetupQualification.finish();})()`);
      await waitFor(() => evaluate('window.__agentSetupQualification.tabs.at(-1).closed'), 'stale source closes its reserved tab');
      assert.equal(await evaluate('window.__agentSetupQualification.tabs.at(-1).destination ?? null'), null);
      await evaluate(`${root}.querySelector('.hraness-agent-setup__full').textContent=${javascriptLiteral(prompt)}`);

      await evaluate(`(() => {window.__agentSetupQualification.mode = 'blocked';${root}.querySelector('[data-agent-target-mode="copy-and-open"]').click();})()`);
      await waitFor(() => evaluate(`${root}.querySelector('[role=status]').textContent.includes("link's menu")`), 'blocked reservation offers native manual opening');
      assert.equal(await evaluate('window.__agentSetupQualification.written.at(-1)'), prompt);
    }
  } finally {
    await evaluate(`(() => {const s=window.__agentSetupQualification;for(const tab of s.tabs)tab.close();
      if(s.clipboard)Object.defineProperty(navigator,'clipboard',s.clipboard);else delete navigator.clipboard;
      if(s.exec)Object.defineProperty(document,'execCommand',s.exec);else delete document.execCommand;
      window.open=s.open;delete window.__agentSetupQualification;})()`);
  }
  await call('Emulation.setScriptExecutionDisabled', {value: true}, sessionId);
  try {
    await navigate('/docs/agent-setup/', 390, 900);
    const native = await evaluate(`(() => {const roots=[...document.querySelectorAll(${javascriptLiteral(selector)})];
      for(const root of roots)root.querySelector('summary').click();
      return roots.map(root=>({copyHidden:root.querySelector('button').hidden,open:root.querySelector('details').open,
        preview:getComputedStyle(root.querySelector('.hraness-agent-setup__preview')).display,
        source:root.querySelector('.hraness-agent-setup__full').textContent,visible:root.querySelector('.hraness-agent-setup__full').getClientRects().length>0}));})()`);
    assert.deepEqual(native.map(block => block.source), prompts);
    assert.ok(native.every(block => block.copyHidden && block.open && block.preview === 'none' && block.visible), 'Full-source native disclosure must work without JavaScript.');
  } finally { await call('Emulation.setScriptExecutionDisabled', {value: false}, sessionId); }
  return {passed: true, results, completeSourceCopy: true, legacyCopyContract: true, reservedTabGuard: true, deniedAndStaleClose: true, nativeWithoutScript: true};
}
