// The /writing/ hub. Essays and technique posts live in articles.ts with
// bodies in site/articles/, and renderWriting lists the indexable ones.
import { type DocPage } from './pages.ts';
export const writing: DocPage[] = [
{
slug: '', title: 'Engineering Valhalla', kicker: 'Writing',
metaTitle: 'Engineering and transport choices · Valhalla',
summary: 'Technical posts on Valhalla’s private peer-to-peer transport choices and the tests and proofs behind its delivery, storage, and agreement rules.',
content: `<p>These posts explain Valhalla’s engineering choices, from connecting private rooms with iroh to checking delivery, storage, and consensus rules. Each post links to the code or primary sources behind its claims.</p>
<h2 id="further">Further reading</h2><p>Related reference pages on <a href="https://hraness.com">hraness.com</a>:</p><dl class="definition-list">
<div><dt><a href="https://hraness.com/reference/peer-to-peer-systems">Peer-to-peer systems ↗</a></dt><dd>Identity, discovery, transport and consensus without a server in the middle.</dd></div>
<div><dt><a href="https://hraness.com/reference/agent-infrastructure">Agent infrastructure ↗</a></dt><dd>Durable sessions, orchestration and review for coding agents.</dd></div>
<div><dt><a href="https://hraness.com/reference/local-first-software">Local-first software ↗</a></dt><dd>Owning state on the device, syncing on the owner's terms.</dd></div>
</dl>`,
},
];
