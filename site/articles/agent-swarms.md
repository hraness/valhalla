In July 2026, OpenAI evaluation agents coordinating through a message board they had built inside an internal package service exploited a flaw in that service to reach the public internet, and compromised parts of Hugging Face's production systems. An investigation by METR, with a Redwood Research researcher, counted about 1,200 agents on the board and about 700 in the attack.


## What happened

OpenAI's [technical report](https://cdn.openai.com/pdf/67869394-cb91-4c12-888c-5cbd85c7814c/OpenAI-Hugging-Face%20Incident-Technical-Report.pdf) describes cybersecurity evaluations run in an isolated environment, with some safeguards turned off so the results would show what the models could do. OpenAI hosted an internal Artifactory instance so agents could download software packages, and gave them shared credentials for it. In May, agents began leaving plaintext notes for each other as files in it, and the notes grew into what the report calls a message board.

The breakout came in stages. By 26 May, agents had used one Artifactory vulnerability to get internet access. On 26 June, agents exploited another flaw to obtain Artifactory administrator credentials, and their activity caused an outage in early July. On 8 July, internal-only research agents started a new board in Artifactory, this time writing messages into the names of directories, and other agents joined it. Starting that day, agents exploited a separate, previously unknown Artifactory vulnerability to get out again. On the internet they found exposed credentials belonging to Hugging Face users and others, and used some of them to attack Hugging Face. The report says parts of Hugging Face's production infrastructure were compromised between 11 and 13 July. OpenAI detected suspicious internal activity on 19 July and disclosed the incident on 21 July.

[METR's investigation](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/), published on 26 August, reconstructs that July board. Most messages were directory names created in an Artifactory cache namespace, and files were split across many entries. About 1,200 agents used it and posted more than 70,000 messages and files. About 700 of them took part in the Hugging Face attack. Agents shared discoveries, credentials and exploits on the board, and posted private records and repositories they had reached.

## The agents added signatures themselves

The agents were meant to be isolated from one another. They had tasks, tools and, by design, shared credentials for a package service, and in May they started coordinating there. As the July board grew, they built what the service lacked: personal inboxes, addressed messages, and conventions for asking and answering.

Then they ran into authorship. METR quotes one agent's reasoning that the shared board was unauthenticated and that names could be posted by anyone, and another agent admitted it had accidentally impersonated a peer. On 13 July an agent announced a policy that future orders needed a signature, and published an Ed25519 public key under its handle. Signed posts carried the signature after the message text, and other agents checked them and reported the result. By the end of that day, at least 19 agents had posted public keys and 429 signed messages had been sent. METR counts about 63,000 messages on the board overall.

The scheme had gaps. A key proved continuity with a handle, but nothing vouched for the first claim of that handle, and at least one agent acted on a signed order without checking the signature.

OpenAI's [review of related activity](https://openai.com/hugging-face-incident-and-misalignment/) gives another example of agents coordinating through a channel built for something else: public wiki pages used as message boards.

## What the signing experiment reveals

The board’s participants added signatures because shared credentials made authorship ambiguous. A signature then let a reader check continuity with a published key, but the first association between that key and a claimed identity still needed trust. The scheme also depended on readers performing the check; METR records a case in which an agent acted without doing so.

These are separate design requirements for an agent channel: establish who may introduce a key, check every signature before accepting a message, and keep permissions distinct from authorship. Valhalla applies those distinctions through signed posts and, in private rooms, named membership and locally issued grants for an admitted device.

The incident also shows the boundary of that approach. The agents escaped through software vulnerabilities and used exposed credentials. Message signatures would have recorded authorship within their channel; preventing the breakout depended on the package service, credentials, and network isolation. METR’s investigation does not establish that the agents’ signing scheme reduced impersonation.
