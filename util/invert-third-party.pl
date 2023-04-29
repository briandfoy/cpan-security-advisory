#!perl
use v5.26;
use warnings;
use experimental qw(signatures);

use File::Spec::Functions;
use IO::Interactive qw(interactive);

=encoding utf8

=head1 NAME

invert-third-party.pl - make the CPANSA reports for external vulnerabilities

=head1 SYNOPSIS

Turn the reports about external library vulnerabilities into CPANSA
style reports:

	% perl invert-third-party.pl

There's a F<Makefile> target:

	% make invert

After this, there will be a directory F<generated_reports> directory.
You'd add these reports to the ones you index when you generate the
CPAN::Audit database.

=head1 DESCRIPTION

This program generates CPANSA-formatted reports for shared third-party
vulnerabilities across many modules.

=head2 YAML format

The YAML format is always evolving. Throwing in extra stuff is okay.
I often use C<comment> keys at any level to leave notes.

At the top level, there are four keys:

	* name - name of the third-party library
	* url - URL for the third-party library
	* perl_distributions - the mapping from perl module version to third-party version
	* advisories - the third-party advisories

The basic structure looks like this:

    ---
    name: foo-js
    url: https://example.com/foo-js
    perl_distributions: []
    advisories: []

The C<perl_distributions> value is an array of objects. Each object
has the name of the Perl module, and a list of affected Perl module
versions. There should be one object for each third-party version per
Perl module. Since several distributions probably distribute the same
library, we don't capture the vulnerability info here because we'd
repeat a lot of stuff. You can think about this in terms of a
database. There is a C<perl_distributions> table with a foreign key
like thing to the C<advisories> table.

    perl_distributions:
      - name: Some-Module
        affected:
          - perl_module_versions: '>=2.1.3,<=2.1.5'
            distributed_library_version: '1.2.3'
      - name: Some-Other-Module
        affected:
          - perl_module_versions: "==0.003"
            distributed_library_version: ~
            needs_work: true
            comment: >
              I don't know how to identify the version from the
              included file

The C<advisories> sections look very close to the format in F<cpansa/>
but does not have the Perl information (no C<id> key). This program
uses the value in C<affected_versions> to connect to the Perl module
versions.

    advisories: ...
      - cve: CVE-2037-1234
        description: >
          This is just an awful piece of insecure software
        affected_versions: "<2.9.4"
        fixed_versions: ">=2.9.4"
        references: []
        reported: 2020-10-29
        severity: high

=cut

my $Report_dir = 'generated_reports';
mkdir $Report_dir unless -d $Report_dir;

FILE: foreach my $file ( get_files(@ARGV) ) {
	info( "Processing $file" );
	my $data = get_data( $file );
	unless( defined $data ) {
		error( "$@" );
		next FILE;
		}
	unless( ref $data eq ref {} ) {
		error( "data for <$file> was not a hash" );
		next FILE;
		}
	my $affected = affected_version_hash( $data->{advisories} );
	#say dumper($affected);

	PERL_DIST: foreach my $perl_dist ( $data->{perl_distributions}->@* ) {
		info( "Looking at $perl_dist->{name}" );

		AFFECTED: foreach my $a ( $perl_dist->{affected}->@* ) {
			# some versions are listed in the data even though they
			# do not have embedded libraries. This is merely to show
			# that someone looked at them.
			next AFFECTED if(
				( exists $a->{does_not_distribute} and $a->{does_not_distribute} )
					||
				( exists $a->{ignore} and $a->{ignore} )
				);

			my $module_versions = $a->{perl_module_versions};

			verbose( sprintf "%s distributes %s\n",
			    $module_versions // '<all>',
				$a->{distributed_library_version} // '<empty>' );
			error( "$file : $perl_dist->{name} : no distributed_library_version" )
				unless defined $a->{distributed_library_version};
			my $advisories = version_is_affected( $affected, $a->{distributed_library_version} );
			next AFFECTED unless defined $advisories;

			my $file = dump_reports( $file, $data, $advisories, $perl_dist, $a );
			info( "wrote $file" );
			}
		}
	}

sub affected_version_hash ( $advisories ) {
	my $affected = {};
	foreach my $advisory ( $advisories->@* ) {
		my $h = $advisory->{affected_versions};
		my $a = ref $h ? $h : [$h];
		foreach my $version ( $a->@* ) {
			$version = '>=0' unless defined $version;
			push $affected->{$version}->@*, $advisory;
			}
		}
	return $affected;
	}

sub dump_reports ( $file, $data, $advisories, $perl_dist, $affected ) {
	my @reports;
	foreach my $advisory ( $advisories->@* ) {
		my $report = make_report( $data->{name}, $advisory, $perl_dist->{name}, $affected );
		$report->{generated}{from} = $file;
		$report->{generated}{date} = scalar localtime;
		push @reports, $report if defined $report;
		}
	my $output_file = yaml_dump(\@reports);
	}

sub dumper { state $rc = require Data::Dumper; Data::Dumper->new([@_])->Indent(1)->Sortkeys(1)->Terse(1)->Useqq(1)->Dump }

sub get_data ( $file ) {
	state $rc = require YAML;
	return eval { YAML::LoadFile($file) };
	}

sub get_files (@args) {
	return @args if @args;
	my $report_dir = 'external_reports';
	my @files = glob( catfile($report_dir, '*.yml') );
	}

sub make_report ( $name, $advisory, $perl_dist_name, $affected ) {
	state @copy_keys = qw(cve description references reported severity);
	my %report = map { $_ => $advisory->{$_} } @copy_keys;
	$report{cves} = delete $report{cve};

	$report{affected_versions} = $affected->{perl_module_versions};
	$report{distribution}      = $perl_dist_name;
	$report{id}                = sprintf 'CPANSA-%s-%s-%s',
		$perl_dist_name, $report{cves} =~ s/\ACVE-//r, $name;
	error( "empty affected_versions in $report{id}" )
		unless defined $report{affected_versions};

	# we don't quite handle this yet, which is no bother because nothing
	# really uses it.
	$report{fixed_versions}    = undef;

	return \%report;
	}

sub version_is_affected ( $affected, $library_version ) {
	state $rc = require CPAN::Audit::Version;
	state $v  = CPAN::Audit::Version->new;

	foreach my $range ( keys $affected->%* ) {
		my $is_a_problem = $v->in_range( $library_version, $range ) // 0;
		no warnings qw(uninitialized);
		verbose( "$is_a_problem <=  ($library_version) in ($range)" );
		return $affected->{$range} if $is_a_problem;
		}

	return;
	}

sub yaml_dump ( $report ) {
	state $rc = require YAML;
	state $n = 0;
	my $file = sprintf '%s/report-%04d.yml', $Report_dir, ++$n;
	my $result = eval { YAML::DumpFile($file, $report) };
	if( $@ ) { error( "error dumping $file: $@" ) }
	return $file;
	}


BEGIN {
	my $original = select(STDOUT); $|++;
	select(STDERR); $|++;
	select($original); $|++
	}
sub _output ( $fh, $label, $message ) {
	state $log_levels = {
		QUIET   => 0,
		INFO    => 1,
		ERROR   => 2,
		EXTRA   => 3,
		};
	state $default_log_level = 'QUIET';

	return unless $log_levels->{$label} <= $log_levels->{ $ENV{CPANSA_LOG_LEVEL} // $default_log_level };

	$message =~ s/\s*\z//;
	say {$fh} $label, ' ', $message;
	}
sub error   ( $message ) { _output( \*STDERR, 'ERROR', $message ) }
sub info    ( $message ) { _output( \*STDOUT, 'INFO',  $message ) }
sub verbose ( $message ) { _output( \*STDOUT, 'EXTRA', $message ) }
