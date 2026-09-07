<!--
Copyright (c) 2026 Stable State Consulting Ltd
SPDX-License-Identifier: MIT
-->

# Releasing CableProbe to PyPI

Publishing is automated. Creating a **GitHub Release** runs
[`.github/workflows/python-publish.yml`](.github/workflows/python-publish.yml),
which builds the package and uploads it to
[PyPI](https://pypi.org/project/cableprobe/) via trusted publishing (OIDC — no
API token or password is stored anywhere).

One-time setup (already done for this repo):

- A PyPI *trusted publisher* for project `cableprobe`, owner `rosscooney`, repo
  `CableProbe`, workflow `python-publish.yml`, environment `pypi`.
- A GitHub Actions environment named `pypi`.

> The commands below use `origin` as the remote name (the default for a fresh
> `git clone`). Run `git remote -v` to check; on some existing checkouts of this
> repo the remote is called `Github` — substitute accordingly.

## Step by step

### 1. Make your code changes and commit them

```bash
git checkout -b my-change
# ... edit code ...
pytest                      # must pass
git add -A
git commit -m "Describe the change"
git push -u origin my-change
```

Open a pull request, get it reviewed, and merge it to `main`.

### 2. Bump the version

Every release needs a new version number. Edit the `version` field in
[`pyproject.toml`](pyproject.toml):

```toml
[project]
version = "0.1.1"        # was 0.1.0
```

Use [semantic versioning](https://semver.org/): patch (`0.1.1`) for fixes, minor
(`0.2.0`) for new features, major (`1.0.0`) for breaking changes.

```bash
git checkout main && git pull
git checkout -b release-0.1.1
git commit -am "Bump version to 0.1.1"
git push -u origin release-0.1.1
# open PR, merge to main
```

### 3. Sanity-check the build locally (optional but recommended)

```bash
git checkout main && git pull
python -m pip install build twine
python -m build
python -m twine check dist/*
rm -rf dist build            # don't commit these; they're gitignored
```

### 4. Tag and release

```bash
git checkout main && git pull

# annotated tag matching the pyproject version, prefixed with "v"
git tag -a v0.1.1 -m "CableProbe 0.1.1"
git push origin v0.1.1

# create the GitHub Release -> triggers the publish workflow
gh release create v0.1.1 --title "v0.1.1" --notes "What changed in this release."
```

No `gh`? Do the release by hand at
`https://github.com/rosscooney/CableProbe/releases/new?tag=v0.1.1` — set the
title, write the notes, click **Publish release**.

### 5. Watch it publish

```bash
gh run watch --exit-status "$(gh run list --workflow python-publish.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Or open the **Actions** tab on GitHub. When it's green:

```bash
pipx install "cableprobe==0.1.1"     # or: pip install --upgrade cableprobe
cableprobe --version
```

## If the publish fails

- **`non-existent or private` / trusted publishing error** — the PyPI trusted
  publisher or the GitHub `pypi` environment is misconfigured. Fix it at
  <https://pypi.org/manage/project/cableprobe/settings/publishing/> and in the
  repo's *Settings → Environments*, then re-run the failed workflow.
- **`File already exists`** — that version was already uploaded. PyPI does not
  allow re-uploading a version. Bump to the next version and release again.
- **Build failed** — reproduce locally with `python -m build` and fix
  `pyproject.toml` / packaging.

A failed release can be retried: delete the GitHub Release and its tag
(`git push origin :refs/tags/v0.1.1` and delete it on GitHub), fix the problem,
then repeat from step 4.
