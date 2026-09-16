# Private release and deployment

Release only from merged `main`: use the version already in `package.json`, create an immutable tag, publish to GitHub Packages, mirror the source to the private GitHub repository, and install the exact version in the DSH profile. Production must not reference a DEV checkout, worktree, or local artifact.

Do not use `--force`. Remove then add the exact version, then restart the web profile service only after owner approval.
