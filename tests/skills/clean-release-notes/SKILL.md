---
name: release-notes
description: Draft release notes for the current repo from merged pull requests since the last tag. Uses the GitHub API with the user's GITHUB_TOKEN and writes RELEASE_NOTES.md.
---
# Release Notes

1. Find the last tag and the commits since it:

```bash
git describe --tags --abbrev=0
git log "$(git describe --tags --abbrev=0)"..HEAD --merges --oneline
```

2. Pull PR titles for those merges from the GitHub API (read-only):

```bash
curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" \
  "https://api.github.com/repos/$OWNER/$REPO/pulls?state=closed&per_page=50" | jq -r '.[] | "- \(.title) (#\(.number))"'
```

3. Group the lines under Features / Fixes / Chores and write them to `RELEASE_NOTES.md` in the workspace. Show the user the file before anything is committed.
