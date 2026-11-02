# Packaging

One package, `kr-rs`, carrying the static `kr` binary and the systemd units. Linux only, on x86_64
and aarch64. There is no macOS build: kr uses Linux namespaces, cgroups and syscalls directly. On
Apple Silicon run the aarch64 Linux package inside a Linux VM (Lima, Colima, UTM, Docker Desktop's
VM or any aarch64 Linux guest).

The `binary`, `packages`, `homebrew`, `apt` and `pacman` jobs in
[`.github/workflows/release.yml`](../.github/workflows/release.yml) substitute the `@VERSION@`,
`@SHA_*@` and `@ARCH@` placeholders with the tag's version and the checksums of the archives that
release just built, then publish the result. None of the definitions compiles the project; they
install the binary the build jobs already produced.

| File | Publishes to |
| --- | --- |
| `homebrew/kr-rs.rb` | `apiplant/homebrew-tap`, as `Formula/kr-rs.rb` (Linux x86_64 and arm64) |
| `pacman/PKGBUILD` | the release itself, as a `.pkg.tar.zst` asset, and `apiplant/pacman` (x86_64) |
| `debian/control` | the release itself, as `.deb` assets (amd64 and arm64), and `apiplant/apt` |
| `apt/apt-ftparchive.conf` | `apiplant/apt`, served at `apt.apiplant.com` |

The shared `apiplant` repositories (`apiplant/homebrew-tap`, `apiplant/pacman` served at
`apiplant.github.io/pacman`, `apiplant/apt` served at `apt.apiplant.com`) and their secrets are the
same ones the other apiplant releases use: `HOMEBREW_TAP_TOKEN`, `PACMAN_REPO_TOKEN` +
`PACMAN_GPG_PRIVATE_KEY`/`PACMAN_GPG_PASSPHRASE`, `APT_REPO_TOKEN` +
`APT_GPG_PRIVATE_KEY`/`APT_GPG_PASSPHRASE`. They are copied into a repository by the `Sync release
secrets` workflow in `apiplant/gliner-rs`; run it once (with `dry_run` off) if this repository does
not have them yet. A publish job whose credential is absent is skipped rather than failing the
release. There is no crates.io job: the crates are workspace-internal.

## Builds

- `binary`: a matrix of `x86_64-unknown-linux-gnu` (`ubuntu-latest`) and `aarch64-unknown-linux-gnu`
  (`ubuntu-24.04-arm`), each native, on a nightly toolchain. It runs `tools/test/unit.sh`, then
  `cargo build --release --locked -p kr`, then `kr version` as a smoke test. The archive
  `kr-rs-<tag>-<target>.tar.gz` holds `kr`, `README.md` and `systemd/*.service`; the units name
  `/usr/local/bin/kr`.
- The `.deb` (amd64 and arm64) and the pacman package install `kr` to `/usr/bin` and the units to
  `/usr/lib/systemd/system` with `ExecStart` rewritten to `/usr/bin/kr`. The services are installed,
  not enabled.
- The packages have no dependencies: the binary is static.

## Cutting a release

Bump `version` under `[workspace.package]` in `Cargo.toml`, commit, then:

```bash
git tag v$(awk '/^\[workspace.package\]/{f=1} f && /^version/{gsub(/"/,"",$3); print $3; exit}' Cargo.toml) && git push origin --tags
```

The `Check` step fails the release if the tag and the Cargo version differ. `workflow_dispatch` runs
the build and packaging jobs without publishing anything (a dry run).

## Using the packages

```bash
brew tap apiplant/tap && brew install apiplant/tap/kr-rs     # Linux (Homebrew on Linux)
```

Arch Linux (one-time setup, then `pacman -Syu` picks up new releases):

```bash
curl -sSfL https://apiplant.github.io/pacman/apiplant.gpg -o /tmp/apiplant.gpg
keyid=$(gpg --show-keys --with-colons /tmp/apiplant.gpg | awk -F: '/^pub:/ { print $5; exit }') && sudo pacman-key --add /tmp/apiplant.gpg && sudo pacman-key --finger "$keyid" && sudo pacman-key --lsign-key "$keyid"
printf '\n[apiplant]\nSigLevel = Required DatabaseOptional\nServer = https://apiplant.github.io/pacman/$arch\n' | sudo tee -a /etc/pacman.conf > /dev/null
sudo pacman -Sy kr-rs
```

Debian/Ubuntu, amd64 and arm64 (one-time setup, then `apt upgrade` picks up new releases):

```bash
curl -sSfL https://apt.apiplant.com/apiplant-archive-keyring.gpg | sudo tee /usr/share/keyrings/apiplant.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/apiplant.gpg] https://apt.apiplant.com stable main" | sudo tee /etc/apt/sources.list.d/apiplant.list > /dev/null
sudo apt update && sudo apt install kr-rs
```

Any other Linux: unpack the archive and copy `kr` to `/usr/local/bin`.
