#!perl
use v5.26;
use warnings;
use experimental qw(signatures);

use File::Spec::Functions;
use IO::Interactive qw(interactive);

=head1 NAME

invert-third-party.pl - make the CPANSA reports for external vulnerabilities

=head1 SYNOPSIS

Turn the reports about external library vulnerabilities into CPANSA
style reports:

	% perl invert-third-party.pl

There's a F<Makefile> target:

	% make invert

After this, there will be a directory F<generated_reports> directory.

=head1 DESCRIPTION

=cut

my $Report_dir = 'generated_reports';
mkdir $Report_dir unless -d $Report_dir;

FILE: foreach my $file ( get_files(@ARGV) ) {
	info( "Processing $file" );
	my $data = get_data( $file );
	unless( defined $data ) {
		error( "ERROR: $@" );
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
	$message =~ s/\s*\z//;
	say {$fh} $label, ' ', $message;
	}
sub error   ( $message ) { _output( \*STDERR, 'ERROR', $message ) }
sub info    ( $message ) { _output( \*STDOUT, 'INFO',  $message ) }
sub verbose ( $message ) { _output( \*STDOUT, 'EXTRA', $message ) }


__END__
---
- affected_versions: "<=2.26"
  cves:
    - CVE-2010-1447
  description: >
    The Safe (aka Safe.pm) module 2.26, and certain earlier versions,
    for Perl, as used in PostgreSQL 7.4 before 7.4.29, 8.0 before
    8.0.25, 8.1 before 8.1.21, 8.2 before 8.2.17, 8.3 before 8.3.11,
    8.4 before 8.4.4, and 9.0 Beta before 9.0 Beta 2, allows
    context-dependent attackers to bypass intended (1) Safe::reval and
    (2) Safe::rdo access restrictions, and inject and execute
    arbitrary code, via vectors involving subroutine references and
    delayed execution.
  distribution: Safe
  fixed_versions: ">=2.27"
  id: CPANSA-Safe-2010-1447
  references:
    - https://bugs.launchpad.net/bugs/cve/2010-1447
    - http://www.vupen.com/english/advisories/2010/1167
    - http://secunia.com/advisories/39845
    - http://www.postgresql.org/about/news.1203
    - http://security-tracker.debian.org/tracker/CVE-2010-1447
    - https://bugzilla.redhat.com/show_bug.cgi?id=588269
    - http://www.securitytracker.com/id?1023988
    - http://osvdb.org/64756
    - http://www.securityfocus.com/bid/40305
    - http://secunia.com/advisories/40052
    - http://www.redhat.com/support/errata/RHSA-2010-0458.html
    - http://www.openwall.com/lists/oss-security/2010/05/20/5
    - http://www.mandriva.com/security/advisories?name=MDVSA-2010:116
    - http://www.redhat.com/support/errata/RHSA-2010-0457.html
    - http://www.mandriva.com/security/advisories?name=MDVSA-2010:115
    - http://secunia.com/advisories/40049
    - http://www.debian.org/security/2011/dsa-2267
    - http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10705
    - https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A7320
    - https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A11530
  reported: 2010-05-19
  severity: ~
