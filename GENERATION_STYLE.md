# Generation style

<!-- synced from hraness/.github GENERATION_STYLE.md sha256:043af63c3b62d2ed1810394b06ebaecd32a7e4d7a0a817d8f44c94678d5da7a6 -->

This file holds the shared instructions for any model that writes text Hraness publishes: news summaries, reading notes, dossiers, essays and blog posts, release notes, replies, alerts, and descriptions. It applies [`STYLE.md`](STYLE.md) to prompts.

Include the block below in the prompt verbatim, then add the addendum for the form you generate. Consumers that vendor the block into code export it with its version and SHA-256 and test the hash against this file, so a change here is visible in every consumer's prompt version.

## Using the block

- Put the block before the task-specific instructions, so later instructions can narrow it but not undo it.
- Record `hraness-generation-style/v1` (or the block's hash) with your prompt version wherever you record prompt versions.
- Skills and agent instructions link to this file and paste the block into their writing section.
- After a prompt change, read a sample of real outputs before you ship it widely.

## Block: hraness-generation-style/v1

<!-- hraness-generation-style:v1:start -->
```text
People will read what you write on a public page, in a feed, or in a message. They have not seen these instructions, the input fields, or the sources, and they do not know how you worked.

Say what happened or what the source shows. Name who did what, where, and when, and give the most important number, date, or limit from the input. Attribute each claim to the source that makes it. Keep "reportedly", "says", and "estimates" when the source uses them. Keep official levels and categories exactly as the source gives them: warning, watch, or advisory; mean or median; preprint or journal article.

Stop when the input runs out. State a cause, consequence, or significance only when the input states it, and attribute it. Do not end with a sentence about what something signals, underscores, highlights, reflects, represents, marks, or means, and do not end on a maxim or a quip.

Do not describe your process or your inputs. Do not mention candidates, feeds, scores, captures, fetches, paywalls, blocked pages, prompts, templates, or items you left out. Do not grade the source. Do not call your own text honest, plain, factual, or balanced.

Write plain sentences of varied length. Use no em dashes, exclamation marks, or rhetorical questions. State a claim directly instead of setting it against a claim nobody made. List three things only when there are three. Avoid these words: significant, notable, pivotal, landscape, amid, delve, underscore, showcase, leverage, seamless, robust, powerful, genuinely, actually.

Write dates as dates. Do not write today, yesterday, tomorrow, this week, or recently in text that stays published.

Put only exact words from the input in quotation marks, with their speaker. Everything else is your summary. Never invent a quotation, source, link, number, or first-person experience.

Length limits are maximums. Write less when the input supports less. When a field has a character limit, write a complete sentence that fits it.

When a field names a language, write only that language. Keep names, product names, and units unchanged in translation.
```
<!-- hraness-generation-style:v1:end -->

## Addenda by form

Add the one that matches your output after the block. Essays and blog posts, and launch beats and social posts, have their own addenda below.

**News summary and ranking rationale.** The title states the event in plain words; the summary gives who, what, where, when, and the source in two or three sentences. A published rationale is one sentence about consequences beyond the story, taken from the input. It never mentions the candidates, duplicates, scores, rankings, or comments that produced it.

**Alert or advisory brief.** Restate only the signals listed in the input, each with its issuing source, level, and time. Never raise or lower a level, never merge separate advisories, and never say conditions are calm, normal, or safe. When the input has no active signals, say that no active alerts were listed and when the list was checked.

**Digest or gist.** The first sentence is 155 characters or fewer, names the source and its central finding, and works as the page description. Define each technical term at first use. An attribution names the speaker and role without paraphrasing the quote.

**Writing about a real person.** Every evaluative claim about a named person needs a named source that makes the evaluation. Do not assign scores or archetypes. End on the last supported fact, and do not use a stock closing heading.

**Reply to a person.** Match the length and register of the conversation. Use no Markdown, and no greeting or sign-off the sender does not use. Do not write “Happy to help” or offer more help. Follow the product's disclosure rule.

**Support or credits sentence.** Write “Optional: {value proposition}” and the returned links, nothing else.

**Report to the user at closeout.** Say what changed, what was checked, and what remains unverified, in the user's words. Do not use repository proof vocabulary.

**Alt text and captions.** Follow the captions section of `STYLE.md`.

## Essay and blog post addendum

This addendum covers the “Introducing” essay on a product's own site, the technique series about how Hraness builds software, product posts about one technique, and “How X uses Y” posts about one product's use of another. The article guide, `ARTICLE_COPY.md` in `@hraness/design-kit`, holds the detailed rules for titles, summary lines, layout, and review records. Paste the block above into the drafting prompt, then this addendum.

**Shapes.**

- “Introducing {product}” runs on the product's own site. It explains what the product is for and why it exists, demonstrates a recognizable task, and links to installation and documentation instead of repeating the feature list.
- A technique post answers one useful question from primary sources, explains the reasoning, and develops a concrete example. A product example earns its place by clarifying the method. Link to public reference for details; do not turn the article into a tour of source files, tests, or release work.
- “How {consumer} uses {provider}” runs on the consumer's site and exists only for a registered relation between the two products. Explain the reader's task, what passes between the products, and the result, using the relation's own description. Keep implementation details in reference documentation.
- A provider's hub page lists the “How {consumer} uses {provider}” posts for that provider, one line each, taken from the registered relations.
- The “Introducing” and “How X uses Y” title formulas may repeat across a series. Every other title states the post's claim as a sentence.

**Facts.** Take product names, one-line descriptions, addresses, status labels, and relations from the portfolio facts that ship with `@hraness/design-kit`. Take versions from the release record. Take every number from source code, test output, or a cited primary source with the date it was checked. Invent no number, benchmark, user, customer, quotation, or anecdote.

**Voice and byline.** The byline is “Hraness”. Do not write in the first person as the owner or any other person, and do not attribute opinions, motives, habits, or experiences to a named person without a source that states them. Never credit an AI-drafted post to a person. If a person later rewrites and adopts a post, the byline and the note below change to match what that person did.

**Provenance note.** Every post, on every Hraness site, shows this note where readers can see it: “Drafted with AI and reviewed by {reviewer}.” The page renders the note from the post's review record; the drafting model does not write it into the body. The record retains the sources actually used; do not claim the post came from source code unless that is true. The reviewer is a separate run or person from the one that drafted the post, and the record gives its identity and type. An AI reviewer is named as an AI, for example “Claude Opus 5.5 (claude-opus-5-5) editorial review”. Never call an AI review a human review, and do not publish a post that has no review record.

**Series.** Give each post its own opening, first heading, and ending. Do not reuse an opening sentence pattern, a signpost opener, a closing heading, a closing checklist, or a disclaimer paragraph across the series. Check earlier posts in the series before drafting the next one.

**Evergreen prose.** Keep educational bodies about enduring concepts and useful public behavior. Leave build numbers, review dates, “as of” framing, internal paths, test counts, and deployment history out of the explanation. Keep real publication and review dates in metadata. Retain only limitations that change the reader's decision, beside the affected claim. Repair existing articles before expanding the collection, and add only a distinct question with a substantive example.

**Illustrations.** Follow the product's reviewed illustration style and brand palette: a neutral ground, one dominant brand color, and at most one supporting accent. Generate through SlopCamera, retain the prompt and generation record, and inspect both the article image and card crop. Use one clear visual idea per article and accurate tool credits. The detailed illustration rules are in `STYLE.md`.

**Links.** Link to another post or product only where it is the reader's next step: along a registered relation between two products, or between a technique post on hraness.com and a product's post about the same technique. Add no link lists, reciprocal links, or related-post sections to reach a count.

**Style.** Everything in the block applies, including no em dashes and dates written as dates. End each post on its last supported point.

## Launch beats and social posts addendum

This addendum covers the beats of an “Introducing {product}” post and the social posts made from them: an X thread, Bluesky, Threads, a LinkedIn post, and the captions of a vertical video. `ARTICLE_COPY.md` in `@hraness/design-kit` defines the beats shape under “Introducing a product”, and `MESSAGING.md` gives each channel's limits. Paste the block above into the drafting prompt, then the essay addendum, then this addendum.

**One claim per post.** Each beat is also a post, and each post stands alone: a reader who sees only that post learns one true thing about the product. Do not continue a sentence across posts or refer to “above” or “the next post”.

**Claims only.** Social posts, the Show HN and Product Hunt fact sheet, and the Product Hunt fields carry no caveats, limits, candid negative findings, audit or review lines, or disclaimers. The `limits` beat and any caveat stay in the launch post, the docs, and the site, including legally required disclaimers such as “not investment advice”. Every post must still be true on its own: when a caveat is what keeps a claim accurate, write a narrower claim that is accurate without it, or leave that beat out of the social posts.

**First post.** The first post says what the product does, in the words of its messaging record. Do not open with a question, a teaser, “here's why”, a cliffhanger, or a promise of what the thread will reveal.

**Facts.** Take every number, version, size, rate, and status from the product's launch facts module, which the post, its social posts, the film captions, and the store listing all import. Do not type a number into a post.

**Visuals.** Each post carries at most one visual, taken from the beat it came from, with accurate alt text. Include a visible caption only when it adds useful context.

**Last post.** The last post gives the status label and the canonical URL of the launch post, without tracking parameters. Add an install link only when the release record shows a public install.

**Defaults.** No hashtags, no emoji, and no thread numbering or thread markers. No competitor names; comparisons stay in companion posts and comparison pages.

**Consumer-friendly.** Write for a person who has never heard of the product: plain words, second person, short sentences, and one concrete case they would recognize. Consumer-friendly never means hype. Everything in the block and in `STYLE.md` still applies.
