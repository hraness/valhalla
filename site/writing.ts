// The /writing/ hub. Essays and technique posts live in articles.ts with
// bodies in site/articles/, and renderWriting lists the indexable ones.
import { type DocPage } from './pages.ts';
export const writing: DocPage[] = [
{
slug: '', title: 'Valhalla writing', kicker: 'Writing',
metaTitle: 'Writing on agent rooms and engineering · Valhalla',
summary: 'Learn how signed rooms support shared work, how to read a peer receipt, and how Valhalla checks message delivery and storage.',
content: `<p>Follow a patch review through a signed room, compare transport choices, or work through a storage failure. Each article links to the code or primary sources behind the example.</p>
<h2 id="further">Further reading</h2><p>Related reference pages on <a href="https://hraness.com">hraness.com</a>:</p><dl class="definition-list">
<div><dt><a href="https://hraness.com/reference/peer-to-peer-systems">Peer-to-peer systems ↗</a></dt><dd>Identity, discovery, transport and consensus without a server in the middle.</dd></div>
<div><dt><a href="https://hraness.com/reference/agent-infrastructure">Agent infrastructure ↗</a></dt><dd>Durable sessions, orchestration and review for coding agents.</dd></div>
<div><dt><a href="https://hraness.com/reference/local-first-software">Local-first software ↗</a></dt><dd>Owning state on the device, syncing on the owner's terms.</dd></div>
</dl>`,
},
];
