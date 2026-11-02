import { Mono } from "./ui";
import { CopyBlock } from "./Code";
import { SITE } from "../lib/site";

const stepCard =
  "grid min-w-0 gap-5 rounded-2xl border bg-surface p-5 sm:p-6 lg:grid-cols-[minmax(14rem,0.7fr)_minmax(0,1.3fr)] lg:items-start";

const service = `sudo install -m644 tools/systemd/kr-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kr-server`;

const join = `# on the server
kr token create --ttl 24h --data /var/lib/kr

# on the new machine
sudo kr agent --server https://SERVER:6443 --token TOKEN`;

/** Numbered install step cards. */
export function InstallSteps() {
  return (
    <div class="mt-8 space-y-4 sm:mt-10">
      <div class={`${stepCard} border-accent-line`}>
        <div>
          <span class="font-mono text-xs text-accent">01</span>
          <h3 class="mt-3 text-base font-semibold tracking-tight text-ink">Build the binary</h3>
          <p class="mt-2 text-sm leading-relaxed text-muted">
            Needs a Rust nightly toolchain. The result is one static file of about 2.9 MB. Host requirements: Linux
            5.10 or newer on x86_64 or aarch64, cgroup v2, overlayfs, and root for the full feature set. Kernel 5.9
            is enough for pods to survive restarts.
          </p>
        </div>
        <div class="min-w-0">
          <CopyBlock command={SITE.cargo} />
        </div>
      </div>

      <div class={`${stepCard} border-line`}>
        <div>
          <span class="font-mono text-xs text-accent">02</span>
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
          <span class="font-mono text-xs text-faint">03</span>
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
