# Foltivo product model reference

The backend must preserve the agreed product invariants:

- User Libraries support personal creation and publication without organization
  enrollment. Organization Libraries support shared organizational work.
- Libraries own Folios; Books are optional collections referencing Folios.
  Collection membership never grants access to the source.
- Directories organize Documents within Folios. Deleting a Book/reference does
  not delete the source Folio or change other references.
- Enforce current source authorization before content, metadata or counts leave
  the backend. Neither frontend controls nor an identity-provider role alone
  implement resource authorization.
- Working revisions, Git commits and explicitly published Folio versions are
  different identities. Pinning fixes content identity, not permanent access;
  unavailable pins do not silently fall back to latest.

Authoritative product decisions and later changes are tracked in
[frontend #2](https://github.com/Bojan-Ivanovski/foltivo-frontend/issues/2) and
[frontend #4](https://github.com/Bojan-Ivanovski/foltivo-frontend/issues/4).
[Frontend #38](https://github.com/Bojan-Ivanovski/foltivo-frontend/issues/38)
explores broader entity reuse/versioning; it is not approved architecture.
This summary does not select backend schemas, cross-Library reference rules,
roles or retention implementations. Recheck the owning issues before designing
those contracts; keep cross-repository references explicit.
