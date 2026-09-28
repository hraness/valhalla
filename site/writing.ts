// The /writing/ hub. Essays and technique posts live in articles.ts with
// bodies in site/articles/, and renderWriting lists the indexable ones.
import { type DocPage } from './pages.ts';
export const writing: DocPage[] = [
{
slug: '', title: 'How Valhalla tests and proves its rules.', kicker: 'Writing',
metaTitle: 'Writing: how Valhalla tests and proves its rules',
summary: 'Posts on how Valhalla checks its delivery, storage and agreement rules with model checks, randomized tests and proofs.',
content: `<p>These posts show how Valhalla checks its own rules: which bugs a model check must catch, how the ledger is tested across random restarts, and what a proof about quorums covers.</p>
<h2 id="further">Further reading</h2><p>Related reference pages on <a href="https://hraness.com">hraness.com</a>:</p><dl class="definition-list">
<div><dt><a href="https://hraness.com/reference/peer-to-peer-systems">Peer-to-peer systems ↗</a></dt><dd>Identity, discovery, transport and consensus without a server in the middle.</dd></div>
<div><dt><a href="https://hraness.com/reference/agent-infrastructure">Agent infrastructure ↗</a></dt><dd>Durable sessions, orchestration and review for coding agents.</dd></div>
<div><dt><a href="https://hraness.com/reference/local-first-software">Local-first software ↗</a></dt><dd>Owning state on the device, syncing on the owner's terms.</dd></div>
</dl>`,
},
];
