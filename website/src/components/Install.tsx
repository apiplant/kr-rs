import { Badge, Mono } from "./ui";
import { CopyBlock } from "./Code";
import { SITE } from "../lib/site";
import { For } from "solid-js";
import { VERSION, LATEST_RELEASE_URL, PLATFORMS, assetName, downloadUrl } from "../lib/release";

const stepCard =
  "grid min-w-0 gap-5 rounded-2xl border bg-surface p-5 sm:p-6 lg:grid-cols-[minmax(14rem,0.7fr)_minmax(0,1.3fr)] lg:items-start";

const service = `sudo install -m644 tools/systemd/kr-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kr-server`;

const join = `# on the server
kr token create --ttl 24h --data /var/lib/kr

# on the new machine
sudo kr agent --server https://SERVER:6443 --token TOKEN`;

const apt = `curl -sSfL https://apt.apiplant.com/apiplant-archive-keyring.gpg | sudo tee /usr/share/keyrings/apiplant.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/apiplant.gpg] https://apt.apiplant.com stable main" | sudo tee /etc/apt/sources.list.d/apiplant.list > /dev/null
sudo apt update && sudo apt install kr-rs`;

const pacman = `curl -sSfL https://apiplant.github.io/pacman/apiplant.gpg -o /tmp/apiplant.gpg
keyid=$(gpg --show-keys --with-colons /tmp/apiplant.gpg | awk -F: '/^pub:/ { print $5; exit }') && sudo pacman-key --add /tmp/apiplant.gpg && sudo pacman-key --finger "$keyid" && sudo pacman-key --lsign-key "$keyid"
printf '\\n[apiplant]\\nSigLevel = Required DatabaseOptional\\nServer = https://apiplant.github.io/pacman/$arch\\n' | sudo tee -a /etc/pacman.conf > /dev/null
sudo pacman -Sy kr-rs`;

const brew = `brew tap apiplant/tap
brew install apiplant/tap/kr-rs`;

const archive = `tar xzf kr-rs-vVERSION-x86_64-unknown-linux-gnu.tar.gz
sudo install -m755 kr-rs-*/kr /usr/local/bin/kr
sudo install -m644 kr-rs-*/systemd/*.service /etc/systemd/system/`;

function Label(props: { children: string }) {
  return <p class="mb-2 text-xs font-semibold uppercase tracking-[0.14em] text-faint">{props.children}</p>;
}

/** Numbered install step cards. */
export function InstallSteps() {
  return (
    <div class="mt-8 space-y-4 sm:mt-10">
      <div class={`${stepCard} border-accent-line`}>
        <div>
          <div class="flex items-center gap-2">
            <span class="font-mono text-xs text-accent">01</span>
            <Badge tone="accent">Recommended</Badge>
          </div>
          <h3 class="mt-3 text-base font-semibold tracking-tight text-ink">Use a package manager</h3>
          <p class="mt-2 text-sm leading-relaxed text-muted">
            Debian and Ubuntu (amd64, arm64), Arch Linux (x86_64) and Homebrew on Linux (x86_64, arm64), published
            to the shared apiplant repositories. The package installs <Mono>kr</Mono> and the systemd units, and
            does not enable them. Linux only: kr uses Linux namespaces and cgroups.
          </p>
        </div>
        <div class="min-w-0 space-y-5">
          <div>
            <Label>Debian / Ubuntu</Label>
            <CopyBlock command={apt} />
          </div>
          <div>
            <Label>Arch Linux / pacman</Label>
            <CopyBlock command={pacman} />
          </div>
          <div>
            <Label>Homebrew on Linux</Label>
            <CopyBlock command={brew} />
          </div>
        </div>
      </div>

      <div class={`${stepCard} border-line`}>
        <div>
          <span class="font-mono text-xs text-accent">02</span>
          <h3 class="mt-3 text-base font-semibold tracking-tight text-ink">Download the archive</h3>
          <p class="mt-2 text-sm leading-relaxed text-muted">
            One static binary, the systemd units and the README. No installation needed: unpack and run.
          </p>
          <p class="mt-2 text-sm leading-relaxed text-muted">
            <strong class="font-medium text-ink">Apple Silicon:</strong> there is no macOS build, since kr needs a
            Linux kernel. Run the aarch64 Linux archive or package in a Linux VM (Lima, Colima, UTM or Docker
            Desktop's VM).
          </p>
        </div>
        <ul class="min-w-0 space-y-1 border-t border-line pt-4 lg:border-t-0 lg:pt-0">
          <For each={PLATFORMS}>
            {(platform) => (
              <li class="min-w-0">
                <a
                  href={downloadUrl(platform)}
                  title={assetName(platform)}
                  class="flex min-w-0 items-baseline justify-between gap-3 rounded-md py-1 text-muted transition-colors hover:text-ink"
                >
                  <span class="shrink-0 text-sm">{platform.label}</span>
                  <span class="min-w-0 truncate font-mono text-xs text-accent">{assetName(platform)}</span>
                </a>
              </li>
            )}
          </For>
          <li class="pt-2">
            <a href={LATEST_RELEASE_URL} target="_blank" rel="noreferrer noopener" class="text-sm font-medium text-accent hover:text-accent-dim">
              All releases and checksums
            </a>
          </li>
        </ul>
        <div class="min-w-0 lg:col-start-2">
          <CopyBlock command={archive.replace("VERSION", VERSION)} />
        </div>
      </div>

      <div class={`${stepCard} border-line`}>
        <div>
          <span class="font-mono text-xs text-faint">03</span>
          <h3 class="mt-3 text-base font-semibold tracking-tight text-ink">Or build from source</h3>
          <p class="mt-2 text-sm leading-relaxed text-muted">
            Needs a Rust nightly toolchain. The result is one static file of about 5.5 MB. Host requirements: Linux
            5.10 or newer on x86_64 or aarch64, cgroup v2, overlayfs, and root for the full feature set (the nftables
            Service datapath also needs <code>br_netfilter</code> with <code>bridge-nf-call-iptables=1</code>). Kernel
            5.9 is enough for pods to survive restarts.
          </p>
        </div>
        <div class="min-w-0">
          <CopyBlock command={SITE.cargo} />
        </div>
      </div>

      <div class={`${stepCard} border-line`}>
        <div>
          <span class="font-mono text-xs text-accent">04</span>
          <h3 class="mt-3 text-base font-semibold tracking-tight text-ink">Run it as a service</h3>
          <p class="mt-2 text-sm leading-relaxed text-muted">
            The unit files in <Mono>tools/systemd</Mono> set <Mono>KillMode=process</Mono>, which is what lets pods
            keep running while <Mono>kr</Mono> restarts. Use <Mono>kr-agent.service</Mono> on worker nodes.
          </p>
        </div>
        <div class="min-w-0">
          <CopyBlock command={service} />
        </div>
      </div>

      <div class={`${stepCard} border-line`}>
        <div>
          <span class="font-mono text-xs text-faint">05</span>
          <h3 class="mt-3 text-base font-semibold tracking-tight text-ink">Add nodes</h3>
          <p class="mt-2 text-sm leading-relaxed text-muted">
            Create a bootstrap token on the server and give it to the new machine. The agent gets a pod subnet and
            joins the overlay.
          </p>
        </div>
        <div class="min-w-0">
          <CopyBlock command={join} />
        </div>
      </div>
    </div>
  );
}
