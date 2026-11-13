import { DocsLayout } from "./DocsLayout";
import { H1, H2, Lead, P, IC, Section, Table, Note } from "./Prose";

export function DocsBenchmarks() {
  return (
    <DocsLayout>
      <H1>Benchmarks</H1>
      <Lead>
        Measured on one 32-core x86_64 Linux machine, each node in a privileged Docker container, with cached images
        (<IC>pause</IC> and <IC>agnhost</IC>). Memory is the resident set size (RSS) of the <IC>kr</IC> processes.
      </Lead>

      <Section>
        <H2>Size</H2>
        <Table
          head={["", "x86_64", "aarch64"]}
          rows={[
            ["kr binary (stripped, opt-level=z, LTO, panic=abort)", "4.98 MB", "3.96 MB"],
            ["Third-party crates", "0", "0"],
            ["Rust source (13 workspace crates)", "about 119,000 lines", ""],
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
            ["Idle, no pods", "13.3 MB (+1.3 MB helper)", "5.3 MB"],
            ["10 pods", "15.3 MB", "7.1 MB"],
            ["50 pods", "21.4 MB", "11.3 MB"],
            ["100 pods", "28.4 MB", "15.5 MB"],
          ]}
        />
        <P>
          The watch history is limited to 32 MiB, so memory under sustained writes levels off: 62,000 updates of a
          1 KB object (with 100 pods running) leave the server at about 60 MB, the same as after 40,000. Each pod also has
          a sandbox holder process of about 0.4 MB RSS, of which only 80 KB is private.
        </P>
        <P>
          Since pods survive restarts, each running container also has a shim of about 1 MB resident. 200 pods cost
          about 213 MB of shims.
        </P>
      </Section>

      <Section>
        <H2>Latency and throughput</H2>
        <Table
          head={["Operation", "Result"]}
          rows={[
            ["kr server to node Ready (server and one agent)", "about 2 s"],
            ["100 pause pods Deployment, cached image, on one agent", "about 8.6 s to all Running"],
            ["200 pods Running, cached image", "about 43 s"],
            ["Adopting 200 pods after a kill -9", "about 3 s"],
            ["GET /version, new TLS 1.3 connection each time", "p50 1.9 ms, p99 5.5 ms"],
            ["GET /api/v1/namespaces/default/pods (100 pods, 436 KB)", "p50 5.0 ms, p99 8.3 ms"],
            ["New TLS connections under 40 parallel clients", "about 650 per second (client-bound), no failures"],
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
