/** Shared building blocks for documentation pages: no MDX pipeline, just
 *  hand-written TSX using the same primitives as the rest of the site. */

import { For, type ParentProps } from "solid-js";
import type { JSX } from "@solidjs/web";
import { highlight, type HighlightLang } from "../../lib/highlight";

export function H1(props: ParentProps) {
  return <h1 class="text-3xl font-semibold tracking-tight text-ink sm:text-4xl">{props.children}</h1>;
}

export function H2(props: ParentProps<{ id?: string }>) {
  return (
    <h2 id={props.id} class="mt-12 scroll-mt-24 text-xl font-semibold tracking-tight text-ink first:mt-0">
      {props.children}
    </h2>
  );
}

export function H3(props: ParentProps<{ id?: string }>) {
  return (
    <h3 id={props.id} class="mt-8 scroll-mt-24 text-base font-semibold tracking-tight text-ink">
      {props.children}
    </h3>
  );
}

export function P(props: ParentProps) {
  return <p class="mt-3 max-w-3xl text-[0.9375rem] leading-relaxed text-muted">{props.children}</p>;
}

export function Lead(props: ParentProps) {
  return <p class="mt-3 max-w-3xl text-lg leading-relaxed text-muted">{props.children}</p>;
}

export function UL(props: ParentProps) {
  return <ul class="mt-3 max-w-3xl list-disc space-y-1.5 pl-5 text-[0.9375rem] leading-relaxed text-muted">{props.children}</ul>;
}

export function LI(props: ParentProps) {
  return <li>{props.children}</li>;
}

export function IC(props: ParentProps) {
  return <code class="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[0.85em] text-ink">{props.children}</code>;
}

/** Shared max-width for every code box (Pre and CopyBlock alike) so bash
 *  and rust snippets line up at the same width across a page. */
export const CODE_WIDTH = "max-w-4xl";

/** A block of code or console output, no copy button — for output samples
 *  and snippets that aren't meant to be pasted verbatim. Syntax-highlighted
 *  for langs Prism knows (rust, bash, json, console); plain text otherwise. */
export function Pre(props: { children: string; caption?: string; lang?: HighlightLang }) {
  const lang = () => props.lang ?? "text";
  return (
    <div class={`mt-4 ${CODE_WIDTH} overflow-hidden rounded-xl border border-line`}>
      <div class="flex items-center justify-between border-b border-line bg-surface px-4 py-2">
        <span class="text-xs text-faint">{props.caption ?? "output"}</span>
        <span class="font-mono text-[0.6875rem] text-faint">{lang()}</span>
      </div>
      <pre class="overflow-x-auto bg-code-bg p-4 font-mono text-[0.8rem] leading-relaxed text-muted">
        <code class={`language-${lang()}`} innerHTML={highlight(props.children, lang())} />
      </pre>
    </div>
  );
}

export interface FlagRow {
  flag: JSX.Element | string;
  meaning: JSX.Element | string;
}

export function FlagTable(props: { rows: FlagRow[] }) {
  return (
    <div class="mt-4 max-w-3xl overflow-hidden overflow-x-auto rounded-xl border border-line">
      <table class="w-full min-w-[28rem] border-collapse text-left text-sm">
        <tbody>
          <For each={props.rows}>
            {(row, i) => (
              <tr class={i() % 2 === 0 ? "bg-surface" : "bg-canvas"}>
                <td class="whitespace-nowrap border-b border-line px-4 py-2.5 align-top font-mono text-[0.8125rem] text-accent">
                  {row.flag}
                </td>
                <td class="border-b border-line px-4 py-2.5 align-top text-muted">{row.meaning}</td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </div>
  );
}

export function Section(props: ParentProps<{ class?: string }>) {
  return <section class={`pb-4 ${props.class ?? ""}`}>{props.children}</section>;
}

/** A highlighted aside: a warning, a requirement, a caveat. */
export function Note(props: ParentProps<{ title?: string }>) {
  return (
    <div class="mt-4 max-w-3xl rounded-xl border border-accent-line bg-accent-soft px-4 py-3 text-[0.9rem] leading-relaxed text-muted">
      {props.title ? <p class="mb-1 font-medium text-ink">{props.title}</p> : null}
      {props.children}
    </div>
  );
}

/** A header row plus body rows. Cells may be JSX. */
export function Table(props: { head: string[]; rows: (JSX.Element | string)[][] }) {
  return (
    <div class="mt-4 max-w-4xl overflow-hidden overflow-x-auto rounded-xl border border-line">
      <table class="w-full min-w-[28rem] border-collapse text-left text-sm">
        <thead>
          <tr class="bg-surface-2">
            <For each={props.head}>
              {(h) => <th class="border-b border-line px-4 py-2.5 text-xs font-semibold uppercase tracking-[0.1em] text-faint">{h}</th>}
            </For>
          </tr>
        </thead>
        <tbody>
          <For each={props.rows}>
            {(row, i) => (
              <tr class={i() % 2 === 0 ? "bg-surface" : "bg-canvas"}>
                <For each={row}>
                  {(cell, j) => (
                    <td class={`border-b border-line px-4 py-2.5 align-top ${j() === 0 ? "font-mono text-[0.8125rem] text-accent" : "text-muted"}`}>
                      {cell}
                    </td>
                  )}
                </For>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </div>
  );
}
