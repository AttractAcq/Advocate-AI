# Deterministic source bundle

`make build` writes `build/sovereign-source.tar.gz` with normalized file
ownership and timestamps. In a Git workspace it selects tracked inputs from
the index. Untracked experiments, local credentials, generated frontend
`dist` output, installed dependencies and runtime data are excluded. In an
extracted source bundle without Git metadata, it scans the already selected
source tree using the same directory exclusions.

This is a source reproducibility aid, not the signed offline product release.
The product bundle verifier and release gates remain in
[multi-image release](multi-image-release.md). CI builds from a committed
checkout; a local build with modified tracked files reflects those working
tree contents and is not release evidence.
