<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Janus Client Browser Extension


## Requirements

- Firefox (uses `getSecurityInfo()` API)
- Node.js and npm (for building)

## Installation

### Build from source

```bash
./install.sh
```

This will:
1. Install dependencies (`npm install`)
2. Build and package the extension (creates `dist/*.zip`)

### Load in Firefox

1. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Select `manifest.json` or the generated `.zip` file from `dist/`

## Project Structure

```
browser_extension/
├── manifest.json          # Extension manifest (Manifest V2)
├── package.json           # Dependencies (web-ext)
├── install.sh             # Build script
├── src/
│   ├── background/        # Background scripts (webRequest listeners)
│   ├── lib/               # Core logic (parsing, verification, validation)
│   ├── popup/             # Popup UI
│   └── settings/          # Settings page
├── icons/                 # Extension icons
└── dist/                  # Built packages (created by install.sh)
```



