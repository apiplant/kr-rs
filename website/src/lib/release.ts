/** The version shown on the site, read from the workspace manifest at build time. */

import { GITHUB_URL } from "./links";

export const VERSION = __VERSION__;
export const RELEASES_URL = `${GITHUB_URL}/releases`;
