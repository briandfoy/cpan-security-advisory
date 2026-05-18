use utf8;

=encoding utf8


=head1 NAME

xt/ghsa.t - test the bits that look up GitHub Security Advisory IDs

=head1 SYNOPSIS

Run all the author tests:

	% prove xt

Run just this test:

	% perl xt/ghsa.t

=head1 DESCRIPTION

Most CVE reports have an associated GitHub Security Advisory. There is code
in L<Local::CPANSA> to look up that value and add it to a report.

The code for local tools is in F<llib/> since it is not part of the distribution
for L<CPANSA::DB>. These tools are designed to be used within the repo.

=head1 AVAILABILITY

See the F<README.pod> at the top level of the project.

The main source for this repository is in GitHub:

=over 4

=item * L<https://github.com/briandfoy/cpan-security-advisory>

=back

That repo is mirrored to several other services:

=over 4

=item * L<https://bitbucket.com/briandfoy/cpan-security-advisory>

=item * L<https://gitlab.com/briandfoy/cpan-security-advisory>

=item * L<https://codeberg.org/briandfoy/cpan-security-advisory>

=back

=head1 AUTHOR

brian d foy C<< <bdfoy@cpan.org> >>

=head1 COPYRIGHT

Copyright 2022-2026, brian d foy C<< <bdfoy@cpan.org> >>

=cut

use Test::More;

BEGIN {
	if( $] < 5.026 ) {
		plan skip_all => "This test requires Perl 5.026 or later. Skipping";
		exit;
		}
	}

use FindBin qw($Bin);
use lib "$Bin/../util/lib";

my $class = 'Local::CPANSA';

my $get_github_advisories;
subtest 'sanity' => sub {
	use_ok $class;
	can_ok $class, qw(get_github_advisories);
	$get_github_advisories = $class->can('get_github_advisories');
	};

subtest 'good' => sub {
	my @good = (
		[ 'CVE-2025-30672' => [ 'GHSA-jx2w-pp8j-qrcj' ] ],
		);
	foreach my $row ( @good ) {
		subtest $row->[0] => sub {
			my $ghsa_id = $get_github_advisories->($row->[0]);
			is_deeply $ghsa_id, $row->[1];
			};
		}
	};

subtest 'bad' => sub {
	$SIG{'__WARN__'} = sub { () };

	my @bad = (
		[ 'CVE-3025-1234' => [] ],
		[ ''              => [] ]
		);
	foreach my $row ( @bad ) {
		subtest $row->[0] => sub {
			my $ghsa_id = $get_github_advisories->($row->[0]);
			is_deeply $ghsa_id, $row->[1];
			};
		}
	};

done_testing();
