# Merge requirements

The default branch is protected. Changes reach it only through pull requests;
direct pushes and unreviewed changes are not permitted.

Before merge, every pull request must:

- have an approving review from a repository owner, including required
  CODEOWNERS review;
- have no unresolved review conversations;
- pass all required status checks;
- be up to date with the default branch when required by branch protection;
- include tests for behavior changes, or explain why a test is not applicable;
- update relevant documentation; and
- satisfy the dependency policy for dependency or feature changes.

Authors do not approve their own changes. Approval is invalidated by material
changes after review and must be obtained again. Use the repository's allowed
merge methods and keep the resulting default-branch history attributable and
understandable.

Emergency fixes still use a pull request, required review, and required checks.
If repository administrators must apply an exceptional override to protect users
or restore service, they must document the reason and follow-up work in the pull
request. Routine deadlines are not grounds for an override.

Branch protection settings are the enforcement source of truth. This document
records the minimum policy and does not replace stronger configured rules.
