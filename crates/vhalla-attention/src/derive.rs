use super::*;
use vhalla_social::{
    view::{Content, Eligibility, Register, View},
    Body, FacetKind, MentionTarget, Operation, Reaction,
};

pub(super) fn notifications(
    attention: &Attention,
    archive: &Archive,
    now: u64,
    policy: &AttentionPolicy,
    unread_only: bool,
    offset: usize,
    limit: usize,
) -> Result<NotificationSnapshot, Error> {
    if limit == 0 || limit > MAX_PAGE || archive.realm() != attention.reader.realm {
        return Err(Error::Bounds);
    }
    let eligibility = Eligibility::default();
    let view = View::new(archive, now, &eligibility);
    if !view.owner_known(attention.reader.owner)
        || attention
            .reader
            .agent
            .is_some_and(|agent| view.agent_owner(agent) != Some(attention.reader.owner))
    {
        return Err(Error::Context);
    }
    let mut collector = Collector {
        attention,
        policy,
        view: &view,
        selected: BTreeMap::new(),
        requests: BTreeMap::new(),
        coverage: Coverage {
            incomplete: !view.basis().known_history_complete,
            ..Coverage::default()
        },
    };
    let posts = view.posts(None);
    for post in &posts {
        let current = if policy.live {
            &post.observed
        } else {
            &post.committed
        };
        let revisions = match current {
            Content::Present(Register::Resolved { value, .. }) => alloc::vec![*value],
            Content::Present(Register::Conflict { alternatives, .. }) => alternatives.clone(),
            Content::Incomplete | Content::Present(Register::Incomplete) => {
                collector.coverage.incomplete = true;
                continue;
            }
            Content::Retracted { .. } | Content::Present(Register::Empty) => continue,
        };
        let conflict = matches!(current, Content::Present(Register::Conflict { .. }));
        for revision in revisions {
            let Some(state) = view.state(revision.revision) else {
                continue;
            };
            if !admitted(state, policy.live) {
                continue;
            }
            let Some(Body::Social { actor, .. }) =
                archive.get(revision.revision).map(|record| record.body())
            else {
                collector.coverage.incomplete = true;
                continue;
            };
            let base = Notification {
                update: Update {
                    group: Group {
                        recipient: attention.reader.owner,
                        source_owner: post.attribution.owner,
                        target: post.id,
                        reason: Reason::Mention,
                    },
                    event: revision.revision,
                },
                source: Attribution {
                    owner: actor.owner(),
                    actor: *actor,
                },
                recipient_agents: Vec::new(),
                source_post: Some(post.id),
                target: None,
                root: Some(post.root),
                state,
                lane: Lane::Requests,
                positive: !conflict,
                conflict,
                priority: None,
                read: ReadState::Unread,
            };
            let mut mentioned = false;
            let mut recipient_agents = BTreeSet::new();
            for facet in revision.facets {
                match &facet.kind {
                    FacetKind::Mention(MentionTarget::Owner(owner))
                        if *owner == attention.reader.owner =>
                    {
                        mentioned = true;
                    }
                    FacetKind::Mention(MentionTarget::Agent(agent)) => {
                        match view.agent_owner(*agent) {
                            Some(owner) if owner == attention.reader.owner => {
                                mentioned = true;
                                recipient_agents.insert(*agent);
                            }
                            Some(_) => {}
                            None => {
                                collector.coverage.unresolved_mentions += 1;
                                collector.coverage.incomplete = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
            if mentioned {
                let mut item = base.clone();
                item.recipient_agents = recipient_agents.into_iter().collect();
                collector.push(item);
            }
            if let Some(reply) = post.reply {
                if let Ok(parent) = view.post(reply.parent.post) {
                    if parent.attribution.owner == attention.reader.owner {
                        let mut item = base.clone();
                        item.update.group.reason = Reason::Reply;
                        item.target = Some(reply.parent);
                        collector.push(item);
                    }
                } else {
                    collector.coverage.incomplete = true;
                }
            }
            if let (Some(quote), Some(attribution)) = (post.quote, post.quote_attribution) {
                if attribution.owner == attention.reader.owner {
                    let mut item = base.clone();
                    item.update.group.reason = Reason::Quote;
                    item.target = Some(quote);
                    collector.push(item);
                }
            }
            if policy.watched.binary_search(&post.root).is_ok() {
                let mut item = base;
                item.update.group.reason = Reason::WatchedThread;
                item.update.group.target = post.root;
                collector.push(item);
            }
        }
    }

    // Inspect each effective preference slot once. Actual current heads, not raw
    // historical toggles, determine activity and priority. Clear wins remain clear.
    let mut slots = BTreeSet::new();
    for record in archive.records() {
        let Body::Social {
            actor, operation, ..
        } = record.body()
        else {
            continue;
        };
        if !view
            .state(record.id())
            .is_some_and(|state| admitted(state, policy.live))
        {
            continue;
        }
        match operation {
            Operation::Follow { target, .. } if *target == attention.reader.owner => {
                slots.insert((
                    actor.owner(),
                    Reason::Follow,
                    RecordId::from_bytes(*target.as_bytes()),
                ));
            }
            Operation::React { post, .. } => {
                slots.insert((actor.owner(), Reason::Reaction, *post));
            }
            Operation::Repost { post, .. } => {
                slots.insert((actor.owner(), Reason::Repost, *post));
            }
            _ => {}
        }
    }
    for (owner, reason, target) in slots {
        let (heads, conflict) = match reason {
            Reason::Follow => register_heads(view.follow(owner, attention.reader.owner).map(|p| {
                if policy.live {
                    p.observed
                } else {
                    p.committed
                }
            })),
            Reason::Reaction => register_heads(view.reaction(owner, target).map(|p| {
                if policy.live {
                    p.observed
                } else {
                    p.committed
                }
            })),
            Reason::Repost => register_heads(view.repost(owner, target).map(|p| {
                if policy.live {
                    p.observed
                } else {
                    p.committed
                }
            })),
            _ => unreachable!("closed preference slots"),
        };
        let Some(heads) = heads else {
            collector.coverage.incomplete = true;
            continue;
        };
        let target_post = if reason == Reason::Follow {
            None
        } else {
            let Ok(post) = view.post(target) else {
                collector.coverage.incomplete = true;
                continue;
            };
            if post.attribution.owner != attention.reader.owner {
                continue;
            }
            let content = if policy.live {
                &post.observed
            } else {
                &post.committed
            };
            if matches!(content, Content::Retracted { .. }) {
                continue;
            }
            if matches!(
                content,
                Content::Incomplete | Content::Present(Register::Incomplete)
            ) {
                collector.coverage.incomplete = true;
                continue;
            }
            Some(post)
        };
        for event in heads {
            let Some(record) = archive.get(event) else {
                collector.coverage.incomplete = true;
                continue;
            };
            let Body::Social {
                actor, operation, ..
            } = record.body()
            else {
                continue;
            };
            let (positive, reference) = match operation {
                Operation::Follow { following, .. } => {
                    // A false concurrent head wins even if this exact head said true.
                    let effective = view.follow(owner, attention.reader.owner)?;
                    let current = if policy.live {
                        effective.observed
                    } else {
                        effective.committed
                    };
                    if matches!(current, Register::Resolved { value: false, .. }) && *following {
                        continue;
                    }
                    (*following && !conflict, None)
                }
                Operation::React { reaction, .. } => {
                    let effective = view.reaction(owner, target)?;
                    let current = if policy.live {
                        effective.observed
                    } else {
                        effective.committed
                    };
                    if matches!(
                        current,
                        Register::Resolved {
                            value: Reaction::Clear,
                            ..
                        }
                    ) && *reaction != Reaction::Clear
                    {
                        continue;
                    }
                    match reaction {
                        Reaction::Up(revision) => (
                            !conflict,
                            Some(PostRef {
                                post: target,
                                revision: *revision,
                            }),
                        ),
                        Reaction::Down(revision) => (
                            false,
                            Some(PostRef {
                                post: target,
                                revision: *revision,
                            }),
                        ),
                        Reaction::Clear => (false, None),
                    }
                }
                Operation::Repost { revision, .. } => {
                    let effective = view.repost(owner, target)?;
                    let current = if policy.live {
                        effective.observed
                    } else {
                        effective.committed
                    };
                    if matches!(current, Register::Resolved { value: None, .. })
                        && revision.is_some()
                    {
                        continue;
                    }
                    (
                        revision.is_some() && !conflict,
                        revision.map(|revision| PostRef {
                            post: target,
                            revision,
                        }),
                    )
                }
                _ => continue,
            };
            let Some(state) = view.state(event) else {
                continue;
            };
            if !admitted(state, policy.live) {
                continue;
            }
            collector.push(Notification {
                update: Update {
                    group: Group {
                        recipient: attention.reader.owner,
                        source_owner: owner,
                        reason,
                        target,
                    },
                    event,
                },
                source: Attribution {
                    owner,
                    actor: *actor,
                },
                recipient_agents: Vec::new(),
                source_post: None,
                target: reference,
                root: target_post.as_ref().map(|p| p.root),
                state,
                lane: Lane::Requests,
                positive,
                conflict,
                priority: None,
                read: ReadState::Unread,
            });
        }
    }
    let coverage = collector.coverage;
    let retained: Vec<_> = collector
        .selected
        .into_values()
        .chain(collector.requests.into_values())
        .filter(|entry| !unread_only || entry.read != ReadState::Read)
        .collect();
    let total = retained.len();
    let entries = retained.into_iter().skip(offset).take(limit).collect();
    Ok(NotificationSnapshot {
        reader: attention.reader,
        basis: view.basis(),
        entries,
        total,
        coverage,
    })
}

fn admitted(state: RecordState, live: bool) -> bool {
    state == RecordState::Committed || (live && state == RecordState::Provisional)
}
fn register_heads<T>(
    register: Result<Register<T>, vhalla_social::Error>,
) -> (Option<Vec<RecordId>>, bool) {
    match register {
        Ok(Register::Resolved { heads, .. }) => (Some(heads), false),
        // Current conflicting heads are not exposed by Register::Conflict, which
        // contains alternatives plus the same exact head vector in this protocol.
        Ok(Register::Conflict { heads, .. }) => (Some(heads), true),
        Ok(Register::Empty) => (Some(Vec::new()), false),
        _ => (None, false),
    }
}

struct Collector<'a, 'b> {
    attention: &'a Attention,
    policy: &'a AttentionPolicy,
    view: &'a View<'b>,
    selected: BTreeMap<Update, Notification>,
    requests: BTreeMap<Update, Notification>,
    coverage: Coverage,
}
impl Collector<'_, '_> {
    fn push(&mut self, mut item: Notification) {
        let owner = item.source.owner;
        if self.policy.muted.binary_search(&owner).is_ok() {
            return;
        }
        if item
            .root
            .is_some_and(|root| self.policy.muted_threads.binary_search(&root).is_ok())
        {
            return;
        }
        let followed = self
            .view
            .follow(self.attention.reader.owner, owner)
            .is_ok_and(|p| matches!(p.committed, Register::Resolved { value: true, .. }));
        let selected = self.policy.selected.binary_search(&owner).is_ok()
            || followed
            || item.update.group.reason == Reason::WatchedThread;
        item.lane = if selected {
            Lane::Selected
        } else {
            Lane::Requests
        };
        let (priority, exact) = self.attention.read(item.update, item.lane);
        item.read = exact;
        item.priority =
            (selected && item.positive && owner != self.attention.reader.owner).then_some(priority);
        let entries = if selected {
            &mut self.selected
        } else {
            &mut self.requests
        };
        if entries.contains_key(&item.update) {
            return;
        }
        // Keep the lexicographically earliest bounded items per owner, then per
        // lane. Deterministic replacement prevents arrival-dependent admission.
        let same_owner: Vec<_> = entries
            .keys()
            .filter(|key| key.group.source_owner == owner)
            .copied()
            .collect();
        if same_owner.len() >= MAX_PER_OWNER {
            self.coverage.owner_limited = true;
            let last = *same_owner.last().expect("bounded nonempty owner set");
            if item.update >= last {
                return;
            }
            entries.remove(&last);
        }
        let key = item.update;
        entries.insert(key, item);
        if entries.len() > MAX_CANDIDATES {
            entries.pop_last();
            if selected {
                self.coverage.selected_limited = true;
            } else {
                self.coverage.requests_limited = true;
            }
        }
    }
}
