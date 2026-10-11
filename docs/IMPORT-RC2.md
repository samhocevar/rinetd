# Import the tested RC2 engineering bundle

The GitHub fork currently contains the original upstream history. The RC2 engineering bundle was developed separately and its **complete contents have not yet been pushed**. Do not tag or publish a 1.0 release until the source tree is integrated and verified.

From the machine holding the full `rinetd-ng-1.0-rc2-engineering-complete.zip` bundle:

```bash
git clone https://github.com/pastrello/rinetd-ng.git
cd rinetd-ng
git switch develop

mkdir -p /tmp/rinetd-ng-rc2-import
unzip /path/to/rinetd-ng-1.0-rc2-engineering-complete.zip -d /tmp/rinetd-ng-rc2-import
cp -a /tmp/rinetd-ng-rc2-import/rinetd-ng-1.0-rc2/. ./

# Preserve the upstream C sources and history (do not replace them).
# The legacy RC2 bundle expects upstream/src/rinetd.c; import a COPY of
# the original fork files into upstream/ (excluding .git) if that path
# is required, or refactor build.sh to build sources from the Git root.
# Review the patches and run local acceptance before staging.
git status --short
git diff --check
git add -A
git commit -m "build: integrate RC2 engineering bundle and Linux acceptance"
git push origin develop
```

**Note:** The bundle includes a preliminary installer and packaging recipes, *not* certified RPM/DEB artifacts. The automated source-patching approach and non-transactional reload must be reviewed before installing in production.

Maintain `COPYING` and existing copyright headers. Do not import local service configuration containing secrets.
