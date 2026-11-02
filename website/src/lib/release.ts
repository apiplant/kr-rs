/** The published release and its assets: `kr-rs-v<version>-<target>.tar.gz`, one per Linux target. */

import { GITHUB_URL } from "./links";

export const VERSION = __VERSION__;
export const TAG = `v${VERSION}`;

export const RELEASES_URL = `${GITHUB_URL}/releases`;
export const LATEST_RELEASE_URL = `${RELEASES_URL}/tag/${TAG}`;

export interface Platform {
  /** Rust target triple, as it appears in the asset name. */
  target: string;
  label: string;
}

/* Linux only. Apple Silicon Macs run the aarch64 archive inside a Linux VM. */
export const PLATFORMS: Platform[] = [
  { target: "x86_64-unknown-linux-gnu", label: "Linux · x86_64" },
  { target: "aarch64-unknown-linux-gnu", label: "Linux · aarch64 (and Apple Silicon VMs)" },
];

export function assetName(platform: Platform): string {
  return `kr-rs-${TAG}-${platform.target}.tar.gz`;
}

export function downloadUrl(platform: Platform): string {
  return `${RELEASES_URL}/download/${TAG}/${assetName(platform)}`;
}
