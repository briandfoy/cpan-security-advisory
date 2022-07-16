# Contributing

See the
[TODO](https://github.com/briandfoy/cpan-security-advisory/wiki/TODO)
list from the Wiki for a list of distributions that need futher
investigation.

# Report an issue

The simplest thing you might do is report that a CVE we have not
included.

First, check that we don't already have the record:

	$ perl util/find_record CVE-2022-1234

Open an [issue in the briandfoy/cpan-security/advisory GitHub
repo](https://github.com/briandfoy/cpan-security-advisory/issues) and
tell us what the CVE report number is, such as `CVE-2022-1234`.

Alternately, you can leave a note in [the wiki for something we need
to investigate](https://github.com/briandfoy/cpan-security-advisory/wiki/TODO).

## Embedded or external vulnerabilities

We have started tracking vulnerabilities of third-party libraries that
may be distributed or linked into the Perl modules. For example, Tk
distributes the libjpeg library, and Term::Readline::Gnu links against
the previously installed version of readline.

These are compiled in the files under *external_reports/*. Follow the
examples that you see there. There's one file for each third-party
library, and a section that lists each affected Perl module and the
third-party library versions that it distributes. We'll use these
files to generate the reports to feed into the database.

The hardest part of this problem is figuring out which Perl module
versions distribute which versions. This in an intensive, manual
process of inspecting the distributions and sussing out the import
files and their versions.

# Make a Pull Request

But, you can also create the record we need. Most of this is done by
the `util/make_record` program that makes a
[cpan-audit](https://github.com/briandfoy/cpan-audit)-compatible
record:

	$ perl util/make_record CVE-2022-1234

This program tries to guess the distribution name and doesn't always
get it right. Once we read the output and figure out what the
distribution name should be, run it again with the distribution name:

	$ perl util/make_record CVE-2022-1234 Some-Package

Add that record to `cpansa/CPANSA-Some-Package.yml`. If that file already
exists, you'll probably have to strip the leading `---` line from the
`util/make_record` output since you aren't starting the YAML structure.

Once you add the new record, verify that the YAML is valid. Test all
the files:

	$ make test_all

While you are working, you may want to test just the new files because
there are so many:

	$ make test_new

The tests use `yamllint` if it is available. You can do this yourself
to ensure it doesn't warn about anything. We accept the default settings
and fix anything so `yamllint` is content:

	$ yamllint cpansa/*.yml

The [yq](https://github.com/mikefarah/yq) program is a command-line
YAML processor that will complain if there's an error:

	$ yq . cpansa/CPANSA-Some-Package.yml

# Review existing data

The strength of this tool is its reliability. Review the existing data
to verify that it's accurate and up-to-date. There are some things to consider:

* Does the record match the report? Are there typos, cut-and-paste errors, or other weird things?
* Does the problem have a fix? Some records don't know which distribution version solved the problem.
* Is the appropriate CVE listed?
* Is the distribution name correct?
* Are the appropriate references listed?
* Are the references live links?

Once you review a record, feel free to add your details under the `reviewed_by`
key, although you don't have to do this:

```yaml
---
- affected_versions: ">0.24"
  cves:
    - CVE-2012-6143
  description: 'Spoon::Cookie in the Spoon module 0.24 ...'
  distribution: Spoon-Cookie
  fixed_versions: ~
  id: CPANSA-Spoon-Cookie-2012-6143
  references:
    - https://rt.cpan.org/Public/Bug/Display.html?id=85217
    - http://www.securityfocus.com/bid/59834
    - http://seclists.org/oss-sec/2013/q2/318
    - https://exchange.xforce.ibmcloud.com/vulnerabilities/84197
  reported: 2014-06-04
  reviewed_by:
    - name: Your Name
      email: Your Email (or whatever)
      date: YYYY-MM-DD
  severity: ~
```

# Review issues and pull requests

You may want to drop in to review new reports someone else created. In the
simple case, you can add GitHub reactions (thumbs up, whatever) to issues and pull requests, comment
on either, or even have commit access to merge reports. [issue in the briandfoy/cpan-security/advisory GitHub
repo](https://github.com/briandfoy/cpan-security-advisory/issues) if
you'd like commit or admin bits.
