---
name: Custom issue template
about: Describe this issue template's purpose here.
title: ''
labels: ''
assignees: ''

---

Do not report security issues here first! Go to the distribution's maintainers
first and follow their procedures. We only deal with existing reports
and are not a primary source of security reports.

## If this report has a CVE number (Common Vulnerabilities and Exposures), what is that?

If this does not have a CVE number, where is the problem noted?

## Have time to make a Pull Request?

In most cases, pull requests are quick.

If you'd like to make a pull request, the `util/make_record` can help
you:

    $ perl util/make_record CVE-2022-1234

You may be able to edit the file directly in GitHub without having to do
the fork, clone, and other steps.

See [CONTRIBUTING.md] for detailed instructions on pull requests.
