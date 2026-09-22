//! Account-owned, file-only archive orchestration. No live restore or transport.
use super::*;
use files::archive::{Bounds, Reader, Writer};
use vhalla_private_native::archive::{ArchiveExporter, ArchiveInput, ArchiveSession};

const REFUSED: &str = "archive operation refused or interrupted; preserve source file and all stores; resume only exact receiving state with the SAME archive, or use archive-inspect to reconcile a completed finalization; never reset or activate an archive";

pub(super) async fn execute(args: Args, identity: Identity) -> Result<(), String> {
    if args.command == "archive-export" {
        let hint = NativePrivateStore::locate_context(args.store()?).map_err(|_| REFUSED)?;
        let context = context(hint.as_bytes())?;
        let mut source = ArchiveExporter::open(identity, args.store()?, context)
            .await
            .map_err(|_| REFUSED)?;
        let mut output = Writer::create(
            Path::new(args.value("out")?),
            Bounds::new(source.limits())?,
            source.context(),
            source.archive_id().map_err(|_| REFUSED)?,
        )?;
        while let Some(page) = source.next_page().await.map_err(|_| REFUSED)? {
            output.page(page.encrypted_bytes())?;
        }
        output.finish()?;
        source.lock();
        return Ok(());
    }
    let mut input = Reader::open(
        Path::new(args.value("archive")?),
        Bounds::new(args.limits()?)?,
    )?;
    let context = input.context();
    let id = input.archive_id();
    if context.account.as_bytes() != &identity.public_key() {
        return Err(
            "selected account differs from archive header; no destination opened or created".into(),
        );
    }
    if matches!(args.command.as_str(), "archive-import" | "archive-resume") {
        let mut prefix = ArchiveInput::new(identity, context, id).map_err(|_| REFUSED)?;
        loop {
            let page = input.next_page()?.ok_or(REFUSED)?;
            if prefix.push_source(&page).map_err(|_| REFUSED)? {
                break;
            }
        }
        let source_pages = input.pages();
        // A complete prefix is authenticated by create/resume before any store
        // access. Ordinary live state and FORMAT-only partial initialization
        // cannot pass the explicit receiving-purpose resume.
        let mut receiving = if args.command == "archive-import" {
            prefix.create(args.store()?, args.limits()?).await
        } else {
            prefix.resume(args.store()?).await
        }
        .map_err(|_| REFUSED)?;
        let saved_next = receiving.progress().map_err(|_| REFUSED)?.next_page;
        let mut index = source_pages;
        let mut current = input.next_page()?.ok_or(REFUSED)?;
        loop {
            match input.next_page()? {
                Some(next) => {
                    // On resume, recheck the last already committed records
                    // page as an exact retry. Earlier pages are not republished;
                    // retained progress binds their authenticated hash chain.
                    if index >= saved_next || index.checked_add(1) == Some(saved_next) {
                        receiving.append(&current).await.map_err(|_| REFUSED)?;
                    }
                    index = index.checked_add(1).ok_or(REFUSED)?;
                    current = next;
                }
                None => {
                    // Reader verified explicit end marker AND exact EOF before
                    // this candidate can publish final archive-only state.
                    if index != receiving.progress().map_err(|_| REFUSED)?.next_page {
                        return Err(REFUSED.into());
                    }
                    let mut view = receiving.finish(&current).await.map_err(|_| REFUSED)?;
                    view.lock();
                    return Ok(());
                }
            }
        }
    }
    let final_page = input.final_page()?;
    let mut archive = ArchiveSession::open(identity, args.store()?, context, id, &final_page)
        .await
        .map_err(|_| REFUSED)?;
    let seal = archive.seal().map_err(|_| REFUSED)?;
    let revision = seal.source_revision();
    let records = match args.command.as_str() {
        "archive-inspect" => membership(&archive.membership().await.map_err(|_| REFUSED)?),
        "archive-inbox" => {
            let page = archive
                .inbox(args.number("after")?, page_limit(&args)?)
                .await
                .map_err(|_| REFUSED)?;
            json!({"head":page.head,"next":page.next,"records":page.records.iter().map(|entry| {
                json!({"sequence":entry.sequence(),"sender":hex(entry.sender().as_bytes()),
                    "body_hex":hex(entry.body()),"body_utf8":std::str::from_utf8(entry.body()).ok()})
            }).collect::<Vec<_>>()})
        }
        "archive-outbox" => {
            let page = archive
                .outbox(args.number("after")?, page_limit(&args)?)
                .await
                .map_err(|_| REFUSED)?;
            json!({"head":page.head,"next":page.next,"records":page.records.iter().map(|entry| {
                json!({"sequence":entry.sequence(),"operation":hex(entry.operation().as_bytes()),
                    "kind":format!("{:?}",entry.kind()),"artifact_bytes":entry.artifact().map(|value|value.bytes().len())})
            }).collect::<Vec<_>>()})
        }
        _ => return Err(HELP.into()),
    };
    args.json(json!({"kind":"read-only-private-archive","archive_id":hex(&id),
        "source_revision":revision,"coverage":"exact retained source archive; not newest state, clone absence, device transfer or live restore",
        "view":records}))?;
    archive.lock();
    Ok(())
}
