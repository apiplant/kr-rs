import { DocsLayout } from "./DocsLayout";
import { H1, H2, Lead, P, IC, Section, Table, Note } from "./Prose";

export function DocsBenchmarks() {
  return (
    <DocsLayout>
      <H1>Benchmarks</H1>
      <Lead>
        Measured on one 32-core x86_64 Linux machine, each node in a privileged Docker container, with cached images
        (<IC>pause</IC> and <IC>agnhost</IC>). Memory is the resident set size (RSS) of the main <IC>kr</IC> process.
      </Lead>

      <Section>
        <H2>Size</H2>
        <Table
          head={["", "x86_64", "aarch64"]}
          rows={[
            ["kr binary (stripped, opt-level=z, LTO, panic=abort)", "5.46 MB", "4.34 MB"],
            ["Third-party crates", "0", "0"],
            ["Rust source (13 workspace crates)", "about 126,000 lines", ""],
          ]}
        />
        <P>
          For scale, the binary contains the TLS 1.3 stack, X.509, the HTTP/1.1 and WebSocket stacks, the Raft and
          storage engines, the OCI runtime, the API server with its generated protobuf tables, and the controllers.
          Size is watched before each large addition.
        </P>
      </Section>

      <Section>
        <H2>Memory</H2>
        <Table
          head={["State", "kr server", "kr agent"]}
          rows={[
            ["Idle, no pods", "14.0 MB", "6.2 MB"],
            ["10 pods", "15.3 MB", "7.8 MB"],
            ["50 pods", "19.0 MB", "11.8 MB"],
            ["100 pods", "23.5 MB", "16.1 MB"],
            ["200 pods", "32.9 MB", "24.7 MB"],
          ]}
        />
        <P>
          The table is the main process; kr also forks a few small helpers: four offload workers (about 0.5 MB each)
          and an fsync helper (about 1.4 MB) on a server, and two offload workers on an agent.
        </P>
        <P>
          The watch history is limited to 32 MiB, so memory under sustained writes levels off: 62,000 updates of a
          1 KB object (with the 200 pods above still running) leave the server at about 57 MB, the same as after 40,000.
          Each pod also has a sandbox holder process of about 0.65 MB RSS, of which only 80 KB is private.
        </P>
        <P>
          Since pods survive restarts, each running container also has a shim: about 1.9 MB RSS, again only about
          0.1 MB private, so 200 pods add about 23 MB (PSS) in total.
        </P>
      </Section>

      <Section>
        <H2>Latency and throughput</H2>
        <Table
          head={["Operation", "Result"]}
          rows={[
            ["kr server to node Ready (server and one agent)", "about 2 s"],
            ["100 pause pods, cached image, on one agent", "about 8.6 s to all Running"],
            ["200 pause pods, cached image, on one agent", "about 19 s to all Running"],
            ["Adopting 200 pods after a kill -9", "about 2 s"],
            ["GET /version, new TLS 1.3 connection each time", "p50 1.9 ms, p99 3.0 ms"],
            ["GET /api/v1/namespaces/default/pods (200 pods, 857 KB)", "p50 8.2 ms, p99 25 ms"],
            ["New TLS connections under 40 parallel clients", "about 630 per second (client-bound), no failures"],
          ]}
        />
        <Note>
          Numbers vary with hardware. The commands are in <IC>tools/test</IC> (<IC>two-node.sh</IC>,{" "}
          <IC>conformance.sh</IC>, <IC>soak.sh</IC>); memory came from <IC>/proc/PID/status</IC> (VmRSS) and{" "}
          <IC>smaps_rollup</IC>.
        </Note>
      </Section>
    </DocsLayout>
  );
}
