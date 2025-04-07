use Test::More;

use lib qw(lib);

plan skip_all => 'This need v5.26 or later' unless $] >= 5.026;

subtest 'sanity' => sub {
	use_ok Local::CPANSA;
	ok defined &Local::CPANSA::get_github_advisories, 'function is defined';
	};

SKIP: {
	skip "Need CPANSA_GITHUB_TOKEN" unless length $ENV{'CPANSA_GITHUB_TOKEN'};

	subtest 'good' => sub {
		my @good = (
			[ 'CVE-2025-30672' => [ 'GHSA-jx2w-pp8j-qrcj' ] ],
			);
		foreach my $row ( @good ) {
			subtest $row->[0] => sub {
				my $ghsa_id = Local::CPANSA::get_github_advisories($row->[0]);
				is_deeply $ghsa_id, $row->[1];
				};
			}
		};

	subtest 'bad' => sub {
		my @bad = (
			[ 'CVE-3025-1234' => [] ],
			[ '' => [] ],
			);
		foreach my $row ( @bad ) {
			subtest $row->[0] => sub {
				my $ghsa_id = Local::CPANSA::get_github_advisories($row->[0]);
				is_deeply $ghsa_id, $row->[1];
				};
			}
		};
	}

done_testing();
