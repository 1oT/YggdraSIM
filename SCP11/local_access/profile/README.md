Place the default profile package for `LOAD-PROFILE` in this directory.

Profile file behavior:

- If this folder contains exactly one usable file, that file is treated as the default `LOAD-PROFILE` input.
- If this folder contains no files, there is no default local profile file.
- If this folder contains multiple profile files, the loader requires an explicit override path.

Override behavior:

- The local shell accepts `PROFILE /path/to/file` to override the default file.
- `PROFILE-CLEAR` clears the override and returns to directory-based default resolution.

Notes:

- `README.md` is ignored by the resolver.
- Hidden files are ignored by the resolver.
- The `metadata/` subdirectory is reserved for optional metadata JSON overrides used by local SCP11 profile loading.

Related operator docs:

- `../README.md`
- `../../../PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`
