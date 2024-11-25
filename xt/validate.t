use v5.26;

use FindBin qw($RealBin);
use lib "$RealBin/lib";

use Test::More;

use YAML::XS;

my $class    = 'CPANSA::DB';
my $rx_class = 'Local::Rx';

subtest 'sanity' => sub {
	my @classes = (
		[ $class, 'db' ],
		[ $rx_class, 'new' ],
		);

	foreach my $row ( @classes ) {
		my( $c, @m ) = $row->@*;

		use_ok $c or BAIL_OUT( "$c did not compile" );
		can_ok $c, @m;
		}
	};

my $rx;
subtest 'make rx' => sub {
	$rx = $rx_class->new;
	isa_ok $rx, 'Data::Rx';
	};

my $schema;
subtest 'make schema' => sub {
	my $method = 'make_schema';
	can_ok $rx, $method;
	ok defined &get_rx;
	$schema = $rx->$method( get_rx() );
	isa_ok $schema, 'Data::Rx::CoreType';
	can_ok $schema, 'assert_valid';
	};

subtest 'check YAML files' => sub {
	foreach my $file ( sort glob("cpansa/*.yml") ) {
		subtest $file => sub {
			my $data = eval { YAML::XS::LoadFile( $file ) };
			ok defined $data, "Loaded YAML data" or return;
			isa_ok $data, ref {} or return;

			eval { $schema->assert_valid($data) };
			my $at = $@;
			if( ! ref $at ) {
				pass "Data for <$file> was valid";
				}
			else {
				fail( "Data for <$file> was not valid" );
				foreach my $failure ( @{ $at->failures } ) {
					diag( $failure );
					}
				}
			};
		}
	};

done_testing();

sub get_rx () {
	my $advisories = {
		type => '//arr',
		contents => {
			type => '//rec',
			required => {
				affected_versions        => { type => '//arr', contents => { type => '//any', of => [ '//str', '//nil' ] } },
				cves                     => { type => '//arr', contents => { type => "tag:example.com,EXAMPLE:rx/cve" }, },
				description              => { type => '//str' },
				fixed_versions           => { type => '//arr', contents => { type => '//any', of => [ '//str', '//nil' ] } },
				github_security_advisory => { type => '//arr', contents => { type => "tag:example.com,EXAMPLE:rx/ghsa" }, },
				id                       => { type => '//str' },
				reported                 => { type => "//any", of => [ 'tag:example.com,EXAMPLE:rx/cpansa-date', '//nil' ] },
				},
			optional => {
				distributed_version => '//str',
				previous_id    => { type => '//arr', contents => { type => "//str" }, },
				embedded_vulnerability => {
					type => '//rec',
					optional => {
						distributed_version => { type => '//any', of => [ '//str', '//nil' ] },
						name => { type => '//any', of => [ '//str', '//nil' ] },
						affected_versions        => { type => '//any', of => [ '//str', '//nil' ] },
						},
					},
				external_vulnerability => {
					type => '//rec',
					optional => {
						distributed_version => { type => '//any', of => [ '//str', '//nil' ] },
						name => { type => '//any', of => [ '//str', '//nil' ] },
						affected_versions        => { type => '//any', of => [ '//str', '//nil' ] },
						},
					},
				comment     => { type => '//any', of => [ '//str', '//nil' ] },
				severity    => { type => '//any', of => [ '//str', '//nil' ] },
				references  => { type => '//arr', contents => { type => "tag:example.com,EXAMPLE:rx/url" }, },
				reviewed_by => {
					type => '//arr',
					contents => {
						type => '//rec',
						optional => {
							date => { type => "//any", of => [ 'tag:example.com,EXAMPLE:rx/cpansa-date', '//nil' ]  },
							email => '//str',
							name => '//str',
							},
						},
					},
				'x-commit' => { type => '//any', of => [ '//str', '//nil' ] },
				},
			},
		};

	my $record = {
	  type     => '//rec',
	  required => {
		advisories     => $advisories,
		cpansa_version => { type => '//int' },
		distribution   => { type => '//str' },
	  },
	  optional => {
		last_checked   => '//str',
		latest_version => { type => '//any', of => [ '//str', '//nil' ] },
		main_module    => { type => '//any', of => [ '//str', '//nil' ] },
		metacpan       => { type => '//any', of => [ 'tag:example.com,EXAMPLE:rx/url', '//nil' ] },
		repo           => { type => '//any', of => [ 'tag:example.com,EXAMPLE:rx/vcs-url', '//nil' ] },
		darkpan        => { type => '//any', of => [ '//bool', '//nil', { type => '//int', value => 1 }, { type => '//int', value => 0 } ] },
		comment        => '//str',
		url            => { type => '//any', of => [ 'tag:example.com,EXAMPLE:rx/url', '//nil' ] },
		},
	};
}
