# CPAN Security Advisory database

Advisory data lives in `cpansa/CPANSA-<Distribution>.yml`, with one file per distribution.

## Advisory entries

* `id` is `CPANSA-<Distribution>-<year>-<CVE number>`, and the CVE part must match `cves`.
* Every version must fall in either `affected_versions` or `fixed_versions`, with no gaps.
* If an advisory names fixes on more than one branch, list each one in `fixed_versions`.
* Write versions the way the distribution does. For example, Cpanel::JSON::XS `4.33` is not `4.033`.
* List every GHSA ID that appears in `references` under `github_security_advisory`.
* Don't repeat URLs in `references`.
* Quote numeric-looking `latest_version` values. Unquoted, `0.10` can read as `0.1`.
* An `affected_versions` value of `'<0'` means the report was rejected. The advisory stays in the file for completeness.

## Reviewing and staging generated changes

* Bulk updates touch many files, so classify the diffs before staging.
* Stage files with only `last_checked` or `latest_version` changes separately from advisory changes.
* A version format change, such as `'2.023004'` to `v2.23.4`, is not a version update.
