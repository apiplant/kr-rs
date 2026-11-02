import { type ParentProps } from "solid-js";
import { createRouter } from "@solidjs/router";
import { Header } from "./components/Header";
import { Footer } from "./components/Footer";
import { Home } from "./components/Home";
import { DocsOverview } from "./components/docs/Overview";
import { DocsQuickstart } from "./components/docs/Quickstart";
import { DocsNodes } from "./components/docs/Nodes";
import { DocsHa } from "./components/docs/Ha";
import { DocsApi } from "./components/docs/Api";
import { DocsRuntime } from "./components/docs/Runtime";
import { DocsNetworking } from "./components/docs/Networking";
import { DocsCtr } from "./components/docs/Ctr";
import { DocsRootless } from "./components/docs/Rootless";
import { DocsOperations } from "./components/docs/Operations";
import { DocsArchitecture } from "./components/docs/Architecture";
import { DocsBenchmarks } from "./components/docs/Benchmarks";
import { DocsConformance } from "./components/docs/Conformance";
import { DocsDevelopment } from "./components/docs/Development";
import { DocsLimitations } from "./components/docs/Limitations";
import { DocsCli } from "./components/docs/Cli";
import { LinkButton } from "./components/ui";

function Shell(props: ParentProps) {
  return (
    <div class="flex min-h-screen flex-col">
      <Header />
      <main class="flex-1">{props.children}</main>
      <Footer />
    </div>
  );
}

function NotFound() {
  return (
    <div class="mx-auto w-full max-w-6xl px-5 py-28 text-center">
      <p class="font-mono text-sm text-accent">404</p>
      <h1 class="mt-3 text-3xl font-semibold tracking-tight text-ink">No such page</h1>
      <p class="mx-auto mt-3 max-w-md leading-relaxed text-muted">
        The link may be old, or the page may have been renamed.
      </p>
      <div class="mt-8 flex justify-center gap-3">
        <LinkButton href="/" variant="primary">
          Home
        </LinkButton>
      </div>
    </div>
  );
}

const Router = createRouter({
  routes: [
    { path: "/", component: Home },
    { path: "/docs", component: DocsOverview },
    { path: "/docs/quickstart", component: DocsQuickstart },
    { path: "/docs/nodes", component: DocsNodes },
    { path: "/docs/ha", component: DocsHa },
    { path: "/docs/api", component: DocsApi },
    { path: "/docs/runtime", component: DocsRuntime },
    { path: "/docs/networking", component: DocsNetworking },
    { path: "/docs/ctr", component: DocsCtr },
    { path: "/docs/rootless", component: DocsRootless },
    { path: "/docs/operations", component: DocsOperations },
    { path: "/docs/cli", component: DocsCli },
    { path: "/docs/architecture", component: DocsArchitecture },
    { path: "/docs/benchmarks", component: DocsBenchmarks },
    { path: "/docs/conformance", component: DocsConformance },
    { path: "/docs/development", component: DocsDevelopment },
    { path: "/docs/limitations", component: DocsLimitations },
    { path: "*404", component: NotFound },
  ],
});

export const { paths } = Router;

export function App() {
  return <Router>{(props) => <Shell>{props.children}</Shell>}</Router>;
}
