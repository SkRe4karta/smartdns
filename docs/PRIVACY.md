# Public repository cleanup

Managed branches and historical tags were rewritten after creating a private repository backup. Deployment-specific domains, addresses, server aliases, local paths and personal contact addresses were replaced. Historical release binaries and private deployment runbooks were withdrawn; old releases now identify their tags as archived source snapshots. Previous Actions runs/artifacts were removed. Current documentation is written for independent installations.

GitHub account ownership and legitimate contributor attribution remain public. This project does not promise anonymity.

Rewriting branches and tags cannot recall downloaded clones/archives or remove third-party caches. GitHub pull-request refs, old commit views and cached diffs are not writable Git branch refs. A repository owner may need GitHub Support to remove sensitive cached views. Re-clone the repository after history rewriting; do not merge old local history back into maintained branches.

The source secret scanner did not identify live credentials in the managed source history during cleanup. This does not invalidate credentials previously shared elsewhere: rotate any credential known to have been published, and never assume history rewriting revokes it. Production DNS settings, keys, certificates, databases, private backups and rollback locations remain outside this public repository.
