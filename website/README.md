# kr website

The website for [kr](https://github.com/apiplant/kr-rs). Solid 2 RC + Tailwind v4 + Vite, static build.

```bash
pnpm install
pnpm dev       # local dev server
pnpm build     # -> dist/
pnpm check     # types only
```

The version shown on the site is read from `../Cargo.toml` (`[workspace.package]`) at build time. Content lives in `src/lib/site.ts` (home page) and `src/components/docs/` (one file per docs page).
