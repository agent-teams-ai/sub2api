# SheetJS CE

Vendored official `xlsx` 0.20.3 distribution to keep frozen installs independent of CDN availability.

- Source: https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz
- SHA-256: `8dc73fc3b00203e72d176e85b50938627c7b086e607c682e8d3c22c02bb99fe8`
- Upstream commit: `8a7cfd47bde8258c0d91df6a737bf0136699cdf8` (tag `v0.20.3`).
- License: Apache-2.0; the unmodified archive includes LICENSE and upstream attribution.

The npm registry's 0.18.5 predates fixes for CVE-2023-30533 and CVE-2024-22363. Official advisories prescribe >=0.19.3 and >=0.20.2:
https://cdn.sheetjs.com/advisories/CVE-2023-30533
https://cdn.sheetjs.com/advisories/CVE-2024-22363

Registry audit may omit local tarballs. Keep the artifact digest and vendor advisory verification when upgrading; audit success alone does not qualify this dependency. Regenerate the pnpm 9 lock and check real usage-export serialization and the frontend build.
