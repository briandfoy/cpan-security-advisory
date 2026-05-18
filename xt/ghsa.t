use v5.26;
use Test::More;

use lib qw(llib);

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
