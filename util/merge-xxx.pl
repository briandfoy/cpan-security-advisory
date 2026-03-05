#!perl
use v5.10;

=head1 NAME

merge-xxx.pl - update some external_reports with a bit of a kludge

=head1 SYNOPSIS

To update for an external library, it's easier to make the data structure
with F<util/make_record> then merge that in after some hand editing:

Put all the reports in a fake XXX distribution (the F<lib/CPANSA-XXX.yml> file is
ignored in F<.gitignore>):

	% perl util/make_record -p CVE-2026-1234 XXX
	...
	% perl util/make_record -p CVE-2026-1234 XXX
	...

Merge them into the external report, which is slightly different:

	% perl util/merge-xxx.pl external_reports/libfoo.yml cpansa/CPANSA-XXX.yml

Check what's wrong and fix it:

	% prove xt

=head1 DESCRIPTION


=cut

use Mojo::File;
use Mojo::Util;
use YAML::XS;

my( $into, $from ) = @ARGV;

my( $into_yml, $from_yml )	=
	map { YAML::XS::Load( Mojo::File->new($_)->slurp ) }
	@ARGV;

say Mojo::Util::dumper( $into_yml );

my %already_saw =
	map { $_->{cve}, 1 }
	$into_yml->{advisories}->@*;

say Mojo::Util::dumper(\%already_saw);

my @need_from_incoming =
	grep { 0 == grep { exists $already_saw{$_} } $_->{cves}->@* }
	$from_yml->{advisories}->@*;

say Mojo::Util::dumper(\@need_from_incoming);

foreach my $incoming ( @need_from_incoming ) {
	my( $cve ) = $incoming->{cves}->@*; # array normally
	$incoming->{'cve'} = $cve; # but a single value for external_reports
	push $into_yml->{advisories}->@*, $incoming;
	}

Mojo::File->new($into)->spew( YAML::XS::Dump($into_yml) );
