# Vulnerabilities in distributed, third-party libraries

Some Perl modules distribute third-party libraries, such as
jQuery or libgit2. The reports in this directory collect that
information.

The *util/invert-third-party.pl* program then turns them into reports
in the same format as the stuff under *cpansa/*, which CPAN::Audit can
then use to build its database.

See the *util/invert-third-party.pl* program for details on the
particular file format. It's a bit loosey-goosey based on whatever
is needed at the time.

## Contributing

Participate to whatever level you like. Even if you fill in one
data point, you've helped. And, you get closer to some GitHub achievement.

At the moment, there are several files that need to fill in Perl module
versions and which third-party versions they distribute:

* jquery
* bootstrap
* zlib
* freeimage
* jqueryui
* libpcre
* libpng
* plupload
* vue
* chartjs - figure out how which versions those are?
