# Private release and deployment

Release only from merged `main`: use the version already in `package.json`, create an immutable tag, publish to GitHub Packages, mirror the source to the private GitHub repository, and install the exact version in the DSH profile. Production must not reference a DEV checkout, worktree, or local artifact.

Do not use `--force`. Remove then add the exact version, then restart the web profile service only after owner approval.

## Public release migration addendum (0.1.3)

The private release route above is retained as historical procedure for the legacy package. New releases use the public identity @goodandready/dsh-approval-gate on npmjs and a sanitized GitHub product tree. Do not mirror Gitea history or internal planning files. Production must use only an immutable npmjs version; migrate the legacy package with normal DSH remove/add operations and run service plus authenticated route smoke checks.
