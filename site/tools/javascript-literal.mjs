const escapes = Object.freeze({
  '<': '\\u003C',
  '>': '\\u003E',
  '\u2028': '\\u2028',
  '\u2029': '\\u2029',
});

// CDP expressions receive JSON data as a literal. Escape script delimiters and
// JavaScript line separators as well as JSON's own quoting and control bytes.
export function javascriptLiteral(value) {
  const json = JSON.stringify(value);
  if (json === undefined) throw new TypeError('A JavaScript literal requires a JSON value.');
  return json.replace(/[<>\u2028\u2029]/gu, character => escapes[character]);
}
