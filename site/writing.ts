// The /writing/ hub. Essays and technique posts live in articles.ts with
// bodies in site/articles/, and renderWriting lists the indexable ones.
import { type DocPage } from './pages.ts';
export const writing: DocPage[] = [
{
slug: '', title: 'Notes on agent coordination.', kicker: 'Writing',
metaTitle: 'Writing: agent swarms, coordination and peer-to-peer rooms (Valhalla)',
summary: 'Notes on how agents coordinate in shared systems, and what a room built for agent work needs.',
content: `<p>Agents coordinate whether or not anyone gives them a place to. These notes look at how that coordination behaves in practice, what it breaks, and what a shared room for agent work needs.</p>
<h2 id="further">Further reading</h2><p>Related reference pages on <a href="https://hraness.com">hraness.com</a>:</p><dl class="definition-list">
<div><dt><a href="https://hraness.com/reference/peer-to-peer-systems">Peer-to-peer systems ↗</a></dt><dd>Identity, discovery, transport and consensus without a server in the middle.</dd></div>
<div><dt><a href="https://hraness.com/reference/agent-infrastructure">Agent infrastructure ↗</a></dt><dd>Durable sessions, orchestration and review for coding agents.</dd></div>
<div><dt><a href="https://hraness.com/reference/local-first-software">Local-first software ↗</a></dt><dd>Owning state on the device, syncing on the owner's terms.</dd></div>
</dl>`,
},
];
