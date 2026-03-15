package CPANSA::DB;
use strict;
use warnings;

=encoding utf8

=head1 The build file for CPANSA::DB

This build file is a modulino; it works as both a build script and
a module.

To build the distribution, run this file normally:

	% perl Makefile.PL

But, it's more interesting than that. You can load it with C<require>
and call C<arguments> to get the data structure it passes to
C<WriteMakefile>:

	my $package = require '/path/to/Makefile.PL';
	my $arguments = $package->arguments;

Note that C<require>-ing a file makes an entry in C<%INC> for exactly
that name. If you try to C<require> another file with the same name,
even from a different path, C<require> thinks it has already loaded
the file. As such, I recommend you always require the full path to the
file.

The return value of the C<require> is a package name (in this case,
the name of the main module. Use that to call the C<arguments> method.

Even if this distribution needs a higher version of Perl, this bit
only needs v5.8. You can play with the data structure with a primitive
Perl.

=cut

use File::Spec::Functions qw(catfile);

my $module    = __PACKAGE__;
( my $dist = $module ) =~ s/::/-/g;

my $github    = 'https://github.com/briandfoy/cpan-security-advisory';
my $main_file = catfile( 'lib', split /::/, "$module.pm" );

my %WriteMakefile = (
	'MIN_PERL_VERSION' => '5.022',

	'NAME'          => $module,
	'ABSTRACT_FROM' => $main_file,
	'VERSION_FROM'  => $main_file,
	'LICENSE'       => 'artistic_2',
	'AUTHOR'        => 'brian d foy <briandfoy@pobox.com>',

	'PM'            => {
		'lib/CPAN/Audit/DB.pm' => '$(INST_LIB)/CPAN/Audit/DB.pm',
		'lib/CPANSA/DB.pm'     => '$(INST_LIB)/CPANSA/DB.pm',
		},

	'CONFIGURE_REQUIRES' => {
		'ExtUtils::MakeMaker'   => '6.64',
		'File::Spec::Functions' => '0',
		},

	'BUILD_REQUIRES' => {
		},

	# also update cpanfile because cpanm will ignore this since
	# cpanfile exists
	'TEST_REQUIRES' => {
		'Test::More' => '1',
		'YAML::XS'   => '0',
		},

	'PREREQ_PM' => {
		'Carp'     => '0',
		},

	'META_MERGE' => {
		'meta-spec' => { version => 2 },
		resources => {
			repository => {
				type => 'git',
				url  => $github,
				web  => $github,
				},
			bugtracker => {
				web    => "$github/issues",
				},
			homepage => $github,
			},
		},

	'clean' => { FILES => "$dist-* t/.last_run perl-cve-atom.xml" },
	);

sub arguments { \%WriteMakefile }

do_it() unless caller;
sub do_it {
	my $MM ='ExtUtils::MakeMaker';
	my $MM_version =
		eval{ "$MM " . $WriteMakefile{'CONFIGURE_REQUIRES'}{'ExtUtils::MakeMaker'} }
			||
		"$MM 6.64";
	eval "use $MM_version; 1" or die "Could not load $MM_version: $@";
	eval "use Test::Manifest 1.21";

	my $arguments = arguments();
	my $minimum_perl = $arguments->{MIN_PERL_VERSION} || '5.008';
	eval "require $minimum_perl;" or die $@;

	WriteMakefile( %$arguments );
	}

BEGIN {
# remove the useless default `help` target so I can make my own
use ExtUtils::MM_Unix;
no warnings 'redefine';

sub ExtUtils::MM_Unix::top_targets {
# --- Target Sections ---

    my($self) = shift;
    my(@m);

    push @m, $self->all_target, "\n" unless $self->{SKIPHASH}{'all'};

    push @m, sprintf <<'EOF';
pure_all :: config pm_to_blib subdirs linkext
	$(NOECHO) $(NOOP)

subdirs :: $(MYEXTLIB)
	$(NOECHO) $(NOOP)

config :: $(FIRST_MAKEFILE) blibdirs
	$(NOECHO) $(NOOP)
EOF

    push @m, '
$(O_FILES) : $(H_FILES)
' if @{$self->{O_FILES} || []} && @{$self->{H} || []};

#    push @m, q{
# help :
#	perldoc ExtUtils::MakeMaker
#};

    join('',@m);
}



}

BEGIN {
use ExtUtils::MM_Any;
no warnings qw(redefine);

# get rid of the warning about README.pod, because I'm using it.
# It's also in INSTALL.SKIP
sub ExtUtils::MM_Any::libscan {
    my($self,$path) = @_;

    my($dirs,$file) = ($self->splitpath($path))[1,2];
    return '' if grep /^(?:RCS|CVS|SCCS|\.svn|_darcs)$/,
                     $self->splitdir($dirs), $file;

    return $path;
	}
}

sub MY::postamble {
	return <<'POSTAMBLE';
GENERATED=t/.last_run perl-cve-atom.xml generated_reports
CVE_FEED_FILE=perl-cve-atom.xml

.PHONY: invert
invert: ## turn the external_reports into CPANSA-style reports
	$(PERL) util/invert-third-party.pl

.PHONY: lint
lint: invert ## lint the reports
	$(PERL) util/lint_reports

.PHONY: generate
generate: invert ## recreate the data files
	$(PERL) util/generate -o $@

.PHONY: feed
feed: $(CVE_FEED_FILE)

$(CVE_FEED_FILE):
	$(PERL) util/make_feed > $@

.PHONY: test_yaml
test_yaml: ## test all YAML files
	env TEST_CHANGED_ONLY=0 prove -Ilib -b -r xt

######################################################################
# https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help ## Show all the Makefile targets with descriptions
help: ## show a list of targets
	@grep -E '^[a-zA-Z][/a-zA-Z0-9_.-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

POSTAMBLE
	}

no warnings;
__PACKAGE__;
