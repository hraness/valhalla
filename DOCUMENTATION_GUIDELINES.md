# Documentation guidelines

<!-- synced from hraness/.github DOCUMENTATION_GUIDELINES.md sha256:30163f551d9cf7d940b2d8805219d4e73ddb525210e5b6557a13c7309948ac39 -->

Hraness documentation helps a reader learn a skill, complete a task, look up a
fact, or understand a system. Choose the need before choosing the page shape.
Make the next action or conclusion clear, and keep every product claim within
the behavior and evidence that support it.

This is the shared documentation contract for Hraness repositories. It applies
to public and internal documentation, repository and website pages, CLI help,
API and SDK documentation, agent skills, runbooks, and maintained knowledge
notes. The [README guidelines](https://github.com/hraness/.github/blob/main/README_GUIDELINES.md) specialize the repository
front door; [STYLE.md](STYLE.md) owns public prose. Repository rules continue
to own their interfaces, source authority, security boundaries, and delivery
gates.

## Choose the reader's need

[Diátaxis](https://diataxis.fr/) distinguishes four documentation needs. The
distinction is the reader's purpose, regardless of medium or filename.

| Reader need | Form | What the document provides | Example |
| --- | --- | --- | --- |
| Learn through guided practice | Tutorial | A chosen exercise with achievable steps and visible results | Make a first short film from supplied assets |
| Complete a known task | How-to guide | Directions and relevant decisions for a practical goal | Recover a render after its worker stops |
| Find an exact fact | Reference | Consistent descriptions of interfaces, values, behavior, and limits | Render command flags, defaults, outputs, and errors |
| Understand why or how things relate | Explanation | A reasoned model, context, alternatives, and tradeoffs | Why a render receipt binds inputs and tool versions |

The [Diátaxis compass](https://diataxis.fr/compass/) separates practical action
from understanding, and learning from doing work. Use it when a draft's
purpose is unclear. A beginner's exercise and an experienced user's procedure
can use similar commands while serving different needs.

Give a page or clearly delimited section one dominant purpose. Link to the
other forms when the reader's need changes. Remove a theory digression from a
procedure without removing a necessary condition or warning. A reference
table does not become a tutorial by gaining an introduction.

Use the smallest structure that makes these distinctions legible. Four
directories, four top-level sections, equal amounts of content, and a complete
reorganization are not requirements. A small package may use sections in one
file. A larger system may need separate navigation. Improve the reader's next
blocked task before creating empty categories.

## Write each form for its purpose

### Tutorials

A [tutorial](https://diataxis.fr/tutorials/) provides an experience through
which someone can learn. Choose a concrete exercise and guide the learner
through it. State the starting environment and supplied inputs, take small
steps, and show what to observe at useful checkpoints. End with a result the
learner can inspect and a clear route to further practice.

Test the whole exercise in the documented environment. Keep optional choices
and long explanations outside its main path. Use safe sample data, identify
material effects before they occur, and explain any necessary cleanup. A
successful demonstration must not depend on the author's unstated setup.

### How-to guides

A [how-to guide](https://diataxis.fr/how-to-guides/) starts from a task the
reader already wants to accomplish. Name that goal and the conditions under
which the procedure applies. Give actionable steps and branch only for
decisions the real task requires. Supply a completion check and relevant
recovery guidance.

Start and end at useful boundaries. Link prerequisites instead of repeating
an introductory course. Include judgment where a linear recipe would mislead,
such as choosing a recovery action from observed state. Keep exhaustive option
catalogs and architectural discussions in linked reference or explanation.

### Reference

[Reference](https://diataxis.fr/reference/) describes the system accurately
and consistently. Organize it around the public object being consulted, such
as commands, types, configuration, formats, or errors. Cover required and
optional inputs, defaults, units, valid values, outputs, effects, failures,
and compatibility where they apply. Distinguish absence, an empty value, and
an explicit disabled state when the interface does.

Use examples to disambiguate behavior. Keep names synchronized with the
implemented interface and generate repetitive facts from their owning source
when practical. Generated reference still needs checked boundaries and useful
navigation; it does not replace a task guide.

### Explanation

[Explanation](https://diataxis.fr/explanation/) develops understanding. Name
the question, then connect the concepts, mechanisms, context, and tradeoffs
that answer it. Comparisons and alternatives belong here when they clarify a
decision. State the limits of a model and distinguish evidence from inference
or a proposed design.

Link to the procedure or reference that makes the model usable. Keep a
maintained explanation current; preserve historical proposals and source
records as dated records rather than silently rewriting them as present fact.

## Make useful paths complete

A first-use path must reach one supported result beyond installation. Provide
or link the required inputs, show the commands or interactions in order, and
tell the reader how to inspect success. Check that links do not send the
reader in a circle or leave a required step hidden in unrelated reference.

State prerequisites before the action that needs them: release, platform,
runtime, tools, accounts, permissions, data, and expected cost as relevant.
Make placeholders recognizable and explain how to obtain their values. Never
publish credentials, personal filesystem paths, or private operational data
as copyable examples.

For a how-to guide, completeness means reaching its named goal from its
declared starting state. It need not recreate a new user's entire setup. For a
tutorial, verify the complete chosen learning journey.

## Describe the product that exists

Bind instructions and claims to the applicable release, interface, platform,
and configuration. Separate a released capability from development-source
behavior, an optional integration, an experiment, or planned work. Name which
entry point supports a feature when the CLI, SDK, UI, or agent interface differ.

Put material trust boundaries beside the affected step or claim: local and
remote processing, file writes, code execution, credentials, retention,
external publication, paid operations, and recovery. State only relevant
limits. A capability list or sample result does not establish general
compatibility, quality, safety, or performance.

Keep examples, screenshots, captions, and reported results consistent with
their source. Label illustrative output, edited demonstrations, simulations,
and unverified paths. Explain a material omitted dependency or skipped check
where it affects a reader's decision.

Describe the current release in the present tense. Keep chronology in release
notes; durable documentation does not describe behavior relative to earlier
versions.

Educational articles explain a durable idea through a useful question, its
reasoning, and a concrete example. Keep build history, internal file tours,
review dates, and repeated disclaimers out of their bodies. Keep publication
and review metadata truthful, and place a material limitation beside the
decision it affects. Before expanding an article collection, repair stale
names, broken links, weak explanations, and inconsistent illustrations in the
existing pages. Follow `STYLE.md` for the shared illustration direction.

## Adapt to the surface

- **READMEs and documentation landing pages:** orient the reader, establish
  fit, offer a first result, and route to the four needs. A front door can
  contain short, distinct sections without becoming four manuals.
- **Product and marketing pages:** explain fit and show evidence for the
  current capability. Preserve their own reader journey and link to operating
  documentation. A preview should show a reader's task and result; help output
  and release checks belong in reference or installation pages. Use the shared
  syntax highlighter for code and the terminal frame for shell interactions.
  Do not force promotional copy into a tutorial or substitute it for instructions.
- **CLI help and API or SDK reference:** prioritize exact syntax and behavior,
  then link to task examples. Keep generated facts owned by the interface
  definition; check documented examples against the exposed entry point.
- **Agent skills and agent-facing guides:** make a concise task router and
  executable procedure, with exact prerequisites, inputs, outputs, limits,
  and recovery. Link to deeper reference. Keep load-bearing authority and
  safety rules in the instruction surface the agent actually receives.
- **Runbooks and troubleshooting:** start from an observed condition and
  intended outcome. Distinguish diagnosis from mutation, name meaningful stop
  conditions, and verify recovery before recommending a retry.
- **Knowledge notes and design records:** maintain synthesis as explanation
  or reference and keep operational procedures in their owning runbook. Date
  observations and decisions; preserve source material, historical proposals,
  and uncertainty. Do not reshape an immutable record to satisfy a page form.
- **Documentation catalogs:** list reader documents only. Runbooks, release
  checklists, evidence packs, and plans stay in contributor docs or the
  knowledge base.

## Keep surfaces consistent

Choose an owner for each stable fact and repeated example. Keep repository
documentation, website copy, package metadata, help, generated references,
and skills aligned on identity, capabilities, versions, defaults, and trust
boundaries. Different wording and navigation are appropriate for different
readers; contradictory claims are defects.

Change a generated surface through its source. Preserve stable links or supply
redirects when moving pages. Use descriptive link text and meaningful headings;
give images useful alternatives and videos an equivalent way to obtain the
instruction. Keep code and tables readable on the supported display sizes.

Keep one source tree per guide. When a website and GitHub both show the docs,
generate one from the other.

## Review the changed path

Before delivery, verify the parts affected by the change:

1. Read as the named audience. Check that the page's purpose, starting state,
   result, and route to related material are clear.
2. Check commands, interface facts, versions, links, fragments, examples, and
   claims against their owning source. Run the changed complete example when
   authorized and practical; record the actual environment and any unverified
   effects without claiming a skipped path passed.
3. Inspect rendered output when layout, navigation, code wrapping, media, or
   accessibility changed. Use the repository's existing browser or document
   checks where applicable.
4. Run the repository's required checks and review affected generated or
   repeated surfaces. Keep automated checks focused on objective contracts;
   classification and usefulness still need editorial review.

## Adopt the guidance where work happens

Each repository must link this guide from its own root `AGENTS.md` with a
compact instruction covering every documentation surface. Preserve local
instructions and the repository's guide format. Add a contributor-facing link
to the repository's effective contribution guide as well.

The organization `.github/AGENTS.md` applies to that repository; it is not
automatically inherited by other repositories. GitHub can display a
[default CONTRIBUTING file](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/creating-a-default-community-health-file)
for repositories without their own, but does not copy that guidance into their
clones. Explicit local adoption makes the instruction available during work.

Use this compact rule, adapted to the local guide's format:

> For every documentation surface, follow the [Hraness documentation guidelines](https://github.com/hraness/.github/blob/main/DOCUMENTATION_GUIDELINES.md): distinguish guided learning, task completion, factual reference, and explanation; keep each page or section focused on its reader's need, and link between forms. Verify prerequisites, capabilities, effects, and a complete path to the stated result.

This guide adapts Daniele Procida's [Diátaxis framework](https://diataxis.fr/).
The product evidence, cross-surface ownership, and adoption rules above are
Hraness requirements. Improve them through concrete reader and maintenance
evidence, with deliberate adoption in affected repositories.
