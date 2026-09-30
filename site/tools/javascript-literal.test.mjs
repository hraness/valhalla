import {test, expect} from 'bun:test';
import {runInNewContext} from 'node:vm';
import {javascriptLiteral} from './javascript-literal.mjs';

test('CDP literals preserve nested JSON values and every authored string byte', () => {
  const value = {prompt: 'quotes " and \' \\ \b\f\n\r\t\0\u2028\u2029 </script><!-- <div>',
    targets: [{id: 'x', href: 'https://example.test/?a=<b>&c="d"'}], empty: null, numbers: [1, -2, 3.5], enabled: true};
  const literal = javascriptLiteral(value);
  expect(literal).not.toMatch(/[<>\u2028\u2029]/u);
  expect(JSON.parse(literal)).toEqual(value);
  expect(JSON.stringify(runInNewContext('(' + literal + ')'))).toBe(JSON.stringify(value));
});

test('hostile script strings remain data in the CDP expression', () => {
  const value = '</script><script>globalThis.injected = true</script>"; globalThis.injected = true; //\u2028\u2029';
  const context = {};
  const result = runInNewContext('const prompt = ' + javascriptLiteral(value) + '; prompt', context);
  expect(result).toBe(value);
  expect(context.injected).toBeUndefined();
});

test('values with no JSON representation fail before expression construction', () => {
  for (const value of [undefined, () => {}, Symbol('value')]) {
    expect(() => javascriptLiteral(value)).toThrow(TypeError);
  }
  expect(() => javascriptLiteral(1n)).toThrow(TypeError);
  const circular = {}; circular.self = circular;
  expect(() => javascriptLiteral(circular)).toThrow(TypeError);
});
