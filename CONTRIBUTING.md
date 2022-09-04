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

### One possible easy way to contribute

Some of the reports note that a particular Perl module has an external
library, but not which Perl module versions distribute which third-party
library. For example, *external_reports/jquery.yml* is missing a lot of
data.

So, choose some module that you want to investigate. Download all of the
releases. The */util/list_all_releases* queries MetaCPAN and outputs
the download URLs for all releases. Feed that to something to do the
work:

	% cd downloads
	% perl ../util/list_all_releases Sidef | while read u; do curl -O $u; done
    % for f in *.gz; do tar -xzf $f; done

Now let's see what's what:

	% find . -name *jquery*
	./Sidef-22.03/utils/Web interface/js/jquery.autosize.min.js
	./Sidef-22.03/utils/Web interface/js/jquery-2.1.3.min.js
	./Sidef-2.34/utils/Web interface/js/jquery.autosize.min.js
	./Sidef-2.34/utils/Web interface/js/jquery-2.1.3.min.js
	./Sidef-2.33/utils/Web interface/js/jquery.autosize.min.js
	./Sidef-2.33/utils/Web interface/js/jquery-2.1.3.min.js

This one is easy because the version is in the filename, but beware,
the filename isn't always right. Let's just check. This step is particular
to the library we're investigating:

	% find . -name *jquery-* | \
	    while read f; do echo -n $f ' => '  && head -1 "$f" | \
	    perl -pe 's/.*(jQuery v\S+).*/$1/'; done
	./Sidef-22.03/utils/Web interface/js/jquery-2.1.3.min.js  => jQuery v2.1.3
	./Sidef-2.34/utils/Web interface/js/jquery-2.1.3.min.js  => jQuery v2.1.3
	./Sidef-2.33/utils/Web interface/js/jquery-2.1.3.min.js  => jQuery v2.1.3
	./Sidef-22.05/utils/Web interface/js/jquery-2.1.3.min.js  => jQuery v2.1.3
	./Sidef-2.32/utils/Web interface/js/jquery-2.1.3.min.js  => jQuery v2.1.3

In this case it's easy because all versions of the module use the same
jQuery version. Add the version range going from the earliest to the lastest
(which is why I left the filenames in the output):

  - name: Sidef
    affected:
      - perl_module_versions: '>=0.06,<=22.07'
        distributed_library_version: '2.1.3'

But, suppose some of the Perl distro versions had another version of
jQuery. You'd simply add another entry for that third-party version:

  - name: Sidef
    affected:
      - perl_module_versions: '>=0.06,<=15.1.2'
        distributed_library_version: '2.1.3'
      - perl_module_versions: '>=15.1.3,<=22.07'
        distributed_library_version: '3.4.5'

There are a few odd modules that have multiple versions of the same
third-party library. Sometimes that's intentional, but sometimes it
seems that sometimes the full and minimum versions aren't updated in
parallel. Just make another entry for that version even though the
Perl module version ranges overlap:

  - name: Sidef
    affected:
      - perl_module_versions: '>=0.06,<=15.1.2'
        distributed_library_version: '2.1.3'
      - perl_module_versions: '>=0.06,<=15.1.2'
        distributed_library_version: '2.1.5'

If you are really motivated, you can add the last Perl module version
you checked. We might be able to use this to figure out which entries
we need to update later:

  - name: Sidef
    last_version_checked: '22.07'
    affected:
      - perl_module_versions: '>=0.06,<=22.07'
        distributed_library_version: '2.1.3'

Tag your entry if you like, although we could probably figure it out
from commit logs:

  - name: Sidef
    last_version_checked: '22.07'
    affected:
      - perl_module_versions: '>=0.06,<=22.07'
        distributed_library_version: '2.1.3'
    reviewed_by:
      - name: Amelia Camel
        email: amelia@example.com
        date: 2022-06-28

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
