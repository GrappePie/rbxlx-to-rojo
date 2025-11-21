## Unreleased
- Updated dependencies to the latest `rbx-dom` git sources to support modern Roblox types and properties.
- Added robust XML sanitization: removes invalid XML characters, replaces illegal numeric literals (`nan`, `inf`, `1.#IND`, etc.), and skips sanitization inside `SharedString`/`BinaryString` blocks.
- Normalized instance names when writing files/folders to avoid invalid path characters on Windows (e.g., `:`, `*`) while keeping Rojo-compatible structure.
