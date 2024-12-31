# CPAN Security Advisory Database (CPANSA)

This is a database of the security advisories for the Perl modules uploaded to CPAN.

This is a hand-picked database maintained by the Perl community. See [CONTRIBUTING](CONTRIBUTING.md)
or the [issues](https://github.com/briandfoy/cpan-security-advisory/issues) to see how you might
help.

The main mirror is [briandfoy/cpan-security-advisory on GitHub](https://github.com/briandfoy/cpan-security-advisory),
but there are other copies:

- [https://github.com/briandfoy/cpan-security-advisory](https://github.com/briandfoy/cpan-security-advisory)
- [https://bitbucket.org/briandfoy/cpan-security-advisory](https://bitbucket.org/briandfoy/cpan-security-advisory)
- [https://gitlab.com/briandfoy/cpan-security-advisory](https://gitlab.com/briandfoy/cpan-security-advisory)

If you want to mirror a copy, clone the repo and send me the link. Let's
make this more resilient by keeping the data in several places.

## Report new issues to the CPAN Security Group

For new issues without a CVE report, first [report
issues](https://security.metacpan.org/docs/report.html) to the [CPAN
Security Group](https://security.metacpan.org), which can analyze an
issue, collect additional information, and request a CVE. Once a CVE
is issued, we can add it to the CPAN Security Advisories.

## Sources

- metacpan.org - modules Changes files with security fixes
- CVE databases
    - https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml
- OS distributions security advisory feeds:
    - Debian https://www.debian.org/security/dsa
    - FreeBSD http://vuxml.freebsd.org/freebsd/rss.xml
    - Gentoo https://security.gentoo.org/glsa/feed.rss
    - Ubuntu https://usn.ubuntu.com/rss.xml

## Setup your environment

To run the various programs, you'll need some Perl modules. Install
[cpanminus](https://github.com/miyagawa/cpanminus/tree/devel/App-cpanminus)
if you don't already have it:

	$ make -f Makefile.repo setup

## Finding a record

	$ perl util/find_record CVE-2022-1234

## Making a new record

There's a utility to make a record for you from a CVE report:

	$ perl util/make_record CVE-2022-1234

This tool tries to guess the distribution name, but sometimes it can't. If
it doesn't guess the distribution name, simply run it again with the
the distribution name you want:

	$ perl util/make_record CVE-2022-1234 Some-Package

Then, add the report to the file `cpansa/CPANSA-Some-Package.yml`. If
there are already reports in that file, remember to strip the `---` from
the top of the output you just created.

### Record format

Id format: `CPANSA-<dist-name>-<year>-<sequence>`

* `dist-name` is the main module name, not necessarily the affected module in the distribution
* `year` is the year of the report or discovery, not necessarily the year the problem was introduced
* `sequence` is some integer. For single CVE reports, like CVE-2011-1589, use the same sequence number for easier maintenance

Database is in YAML format with a simple structure.

```yaml
- id: CPANSA-Mojolicious-2011-01
  distribution: Mojolicious
  reported: 2011-04-05
  severity: critical
  description: >
    Directory traversal vulnerability in Path.pm in Mojolicious
    before 1.16 allows remote attackers to read arbitrary files via a
    %2f..%2f (encoded slash dot dot slash) in a URI.
  cves:
    - CVE-2011-1589
  references:
    - https://github.com/mojolicious/mojo/commit/b09854988c5b5b6a2ba53cc8661c4b2677da3818
    - https://www.cvedetails.com/cve/CVE-2011-1589/
  affected_versions: "< 1.16"
  fixed_versions: ">= 1.16"
```

There may be an additional `comments` key with more information about
the advisory, especially if the `description` comes from an external
source, such as a CVE report.

If the vulnerability is due to an embedded external library, add the
`embedded_vulnerability` key, e.g.

```yaml
- affected_versions: ">=2.0.0"
  cves:
    - CVE-2021-46322
  description: >
    Duktape v2.99.99 was discovered to contain a SEGV vulnerability via the
    component duk_push_tval in duktape/duk_api_stack.c.
  distribution: JavaScript-Duktape
  fixed_versions: ~
  id: CPANSA-JavaScript-Duktape-2021-46322
  references:
    - https://github.com/svaarala/duktape/issues/2448
    - https://github.com/mamod/JavaScript-Duktape/issues/41
  reported: 2022-01-20
  severity: medium
  embedded_vulnerability:
    name: duktape
    distributed_version: "2.2.0"
```

In some cases, the embedded external library may be part of another
library. Add the parent library in brackets, e.g.
```yaml
  embedded_vulnerability:
     distributed_version: "1.2.11"
     name: zlib[libgit2]
```

There may be cases whether the Perl distribution relies on a
particular version of another library with a security vulnerability
that is installed on the host system, rather than embedded. This may
be indicayed with the `external_vulnerability` key:
```yaml
  external_vulnerability:
     distributed_version: "<=6.3"
     name: readline
```

## Check the results

Check all the files for basic YAML:

	$ make test_all

Checking all the files can take a minute, so you can also just check
the files that have changed:

	$ make test_new

Run the `lint` target to check all of the report files:

	$ make lint

## Command-line checks

For command line checks take a look at [CPAN-Audit](https://metacpan.org/release/CPAN-Audit) module, or the
[cpan-audit repo](https://github.com/briandfoy/cpan-audit).

    $ cpan-audit module Catalyst '>7.0'

To see your new report, you'll have to regenerate the `CPANSA::DB` database since
`CPAN::Audit` does everything locally. That happens in the [cpan-audit repo](https://github.com/briandfoy/cpan-audit),
where this repo is a submodule.

## Maintainer

brian d foy (briandfoy@pobox.com). If you'd like to help, just let me
know by opening as issue. I'm happy to add people as committers on this repo. See
[CONTRIBUTING.md] for more info.

## Credits

* The original author and maintainer was [Viacheslav Tykhanovskyi](https://github.com/vti).
* [Takumi Akiyama](https://github.com/akiym)
* [Takafumi Onaka](https://github.com/onk)
* [Mala](https://github.com/mala)
* [Robert Rothenberg](https://metacpan.org/author/RRWO)

## Contribution

If you know of a security vulnerability that is not present in our
database, feel free to contribute with a Pull Request. Let's make it
as complete as possible!
