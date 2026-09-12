# Icons

**Update:** these files are now committed as placeholder icons (a simple solid-color
square, no real branding), not generated on demand as originally documented here.

The original plan was to leave this folder empty and have each developer run
`npx tauri icon` before their first build. That was wrong: `tauri-build`'s build script
requires these files to exist for **any** `cargo build`/`cargo test` on Windows (it
embeds a Windows resource via `tauri-winres`), not only for `npm run build`/packaging.
Leaving the folder empty meant `cargo test` failed for anyone who hadn't already run the
icon-generation step, which isn't obvious from a `cargo test` failure message.

To replace with real branding later:

```
cd desktop
npx tauri icon path/to/real/logo.png
```

That regenerates all of these files (`32x32.png`, `128x128.png`, `128x128@2x.png`,
`icon.icns`, `icon.ico`) from a source image in one step.
