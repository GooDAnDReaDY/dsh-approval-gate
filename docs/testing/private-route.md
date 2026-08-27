# Private route verification

The route check aligns the package name and Cordis patch with `@goodandready-private/dsh-approval-gate`. The host export remains the stable plugin id because this package has no browser client half.

The tests cover private identity and the existing guard contract: dangerous commands return a denial, safe commands pass, and unrelated tool names are ignored. The isolated DSH profile additionally verifies install, health, host bundle loading, and cleanup while preserving lanmode.
