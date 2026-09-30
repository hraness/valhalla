# macOS release signing

Starting with `v0.2.11`, the Apple silicon CLI uses Developer ID Application
signing for team `8AAP53VTW3`, identifier `dev.hraness.vhalla`, hardened runtime,
and a secure timestamp. A stable identity helps macOS recognize upgrades. It
does not grant Accessibility, Screen Recording, or other user permissions.

The `hraness-apple-release` GitHub environment must permit version tags only,
without required reviewers or a wait timer. Its secrets are
`APPLE_DEVELOPER_ID_P12_BASE64`, `APPLE_DEVELOPER_ID_P12_PASSWORD`,
`APPLE_NOTARY_KEY_P8_BASE64`, `APPLE_NOTARY_KEY_ID`, and
`APPLE_NOTARY_ISSUER_ID`. Build and smoke jobs receive no Apple credentials.
The PKCS#12 bundle must include the Developer ID Application certificate, its
private key, and its issuing Developer ID intermediate certificate (Apple G2
for current certificates). The clean temporary keychain needs that intermediate
to resolve the signing identity. The helper appends its keychain to the user's
existing search list, then deletes only that keychain during cleanup.

The release tag must name the verified main commit. Signing waits for the
complete existing validation workflow. It downloads the unsigned artifact by
immutable ID, verifies the uploaded ZIP digest and run/source identity, and
accepts one bounded arm64 Mach-O executable. It never executes the payload.
The helper signs, waits up to 15 minutes for Apple's `Accepted` result, and
requires `codesign --check-notarization` before creating the final archive and
checksum. Provenance covers those final signed bytes. A separate runner verifies
and smoke-tests the release. The publisher checks both Mac assets against hashes
exported by the signing job before writing a release.

Each uploaded artifact includes its producer's attempt number. A failed job can
reuse a successful producer from an earlier attempt of the same run and source:
its exact ID and digest still select the bytes. Native targets export separate
identities, and the browser also retains its verified manifest hash. Rerunning
all jobs creates new artifacts without replacing earlier evidence.

A timeout, rejection, or interruption stops publication. The
`vhalla-apple-notarization-*` artifact keeps the submission UUID and input,
binary, and upload hashes without credentials. Query that existing submission
before another attempt: rerunning signing submits again. There is no automatic
retry. The helper and an unconditional workflow step remove the temporary
keychain and credential directory. Hard runner termination may prevent the
final diagnostic upload; inspect the completed submission log.

The installer checks the publisher identity, hardened runtime, secure timestamp,
and online notarization before executing new Mac releases. An explicit
`VHALLA_VERSION=v0.2.10` or earlier version preserves the historical checksum
installation. Linux and Windows retain their existing release formats. The
website remains pinned to the published `v0.2.10` until a signed release is
published and the release record is updated. Merging this change alone does
not publish or install a new binary.
