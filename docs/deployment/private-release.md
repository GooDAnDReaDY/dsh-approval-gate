# Private release and deployment

Release only from merged `main`: bump the patch version, create an immutable tag, publish to GitHub Packages, mirror the source to the private GitHub repository, and install the exact version in the DSH profile. Production must not reference a DEV checkout, worktree, or local artifact.
