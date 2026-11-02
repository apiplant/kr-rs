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
            ["kr binary (stripped, opt-level=z, LTO, panic=abort)", "2.87 MB", "2.32 MB"],
            ["Third-party crates", "0", "0"],
            ["Rust source (13 workspace crates)", "about 58,600 lines", ""],
          ]}
        />
        <P>
          For scale, the binary contains the TLS 1.3 stack, X.509, the HTTP/1.1 and WebSocket stacks, the Raft and
          storage engines, the OCI runtime, the API server with its generated protobuf tables, and the controllers.
          The binary has since grown to about 3.1 MB on x86_64 with the later features; size is watched before each
          large addition.
        </P>
      </Section>

      <Section>
        <H2>Memory</H2>
        <Table
          head={["State", "kr server", "kr agent"]}
          rows={[
            ["Idle, no pods", "7.4 MB (+1.2 MB helper)", "3.2 MB"],
            ["10 pods", "9.4 MB", ""],
            ["50 pods", "13.9 MB", ""],
            ["100 pods", "19.8 MB", "9.0 MB"],
          ]}
        />
        <P>
          The watch history is limited to 32 MiB, so memory under sustained writes levels off: 62,000 updates of a
          1 KB object leave the server at about 36 MB. Each pod also has a sandbox holder process of about 0.5 MB RSS,
          of which only 60 to 90 KB is private.
        </P>
        <P>
          Since pods survive restarts, each running container also has a shim of about 1 MB resident. 200 pods cost
          about 250 MB of shims.
        </P>
      </Section>

      <Section>
        <H2>Latency and throughput</H2>
        <Table
          head={["Operation", "Result"]}
          rows={[
            ["kr server to node Ready", "under 1 s"],
            ["100 pause pods Deployment, cached image, single node", "about 2 s to all Running"],
            ["200 pods Running, cached image", "about 38 s"],
            ["Adopting 200 pods after a kill -9", "about 9 s"],
            ["GET /version, new TLS 1.3 connection each time", "p50 4.0 ms, p99 7.9 ms"],
            ["GET /api/v1/namespaces/default/pods (100 pods, 420 KB)", "p50 7.2 ms, p99 10.1 ms"],
            ["New TLS connections to pods under 40 parallel clients", "about 600 per second, no failures"],
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
