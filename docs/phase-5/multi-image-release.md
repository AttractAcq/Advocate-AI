# Signed Core and Console product bundle

Schema 4 extends the offline release directory to bind two image descriptors:
`core` and `console`. Each descriptor names its own `images/<role>.tar`,
digest-pinned image reference, SHA-256 archive hash, Syft inventory and Trivy
scan. The signer validates both archives with crane and runs intake on both
before creating a bundle. Any HIGH, CRITICAL or UNKNOWN finding in either image
denies the product bundle. The verifier checks the signature, exact inventory,
both archive hashes and both intake results at the signed creation time.
An extra archive under `images/`, a missing role or shared evidence path is
rejected.

To pack an approved candidate, provide the evidence descriptors in a JSON
object with exactly `core` and `console` keys. Each value has the same fields
as the `pack-candidate` descriptor plus mandatory archive fields:

```sh
.venv/bin/python -m infrastructure.release.bundle pack-product \
  /path/to/payload /path/to/new-bundle \
  --signing-key /protected/signing-key.pem --version VERSION \
  --images-json /path/to/images.json --crane /path/to/pinned/crane
.venv/bin/python -m infrastructure.release.bundle verify \
  /path/to/new-bundle --trusted-key /protected/trusted-key.pem
```

The [CI product-image rehearsal](product-image-release-rehearsal.md) calls
the same packer against the actual synthetic Core and Console archives. The
earlier Caddy Console findings denied the product bundle. The current pinned
Nginx candidate passed intake and verified the combined bundle. This proves
the local software path; release key custody, licence review, target tests and
site approvals remain open.

The [PR #31 CI result](https://github.com/AttractAcq/Advocate-AI/actions/runs/43889746690)
shows `product_bundle: denied-findings` with Core preflight passing and Console
intake denying four findings. All eight CI jobs passed because denial is the
required behavior for this candidate.

The [PR #32 CI result](https://github.com/AttractAcq/Advocate-AI/actions/runs/43890872823)
shows `product_bundle: verified` with both image preflights passing and zero
unresolved findings in the saved archives. The signer was temporary and does
not authorize release distribution.

# Three-image Knowledge release

The separate [schema 6 vessel bundle format](signed-knowledge-bundle.md)
adds an evidenced `knowledge` image alongside Core and Console. Its installer
and actual-image release qualification remain open.
