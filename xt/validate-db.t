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
	};

subtest 'check db' => sub {
	my $method = 'assert_valid';
	can_ok $schema, $method;
	eval { $schema->$method($class->db) };
	my $at = $@;
	if( ! ref $at ) {
		pass "$class has valid data";
		}
	else {
		fail( "Data for <$class> was not valid" );
		foreach my $failure ( @{ $at->failures } ) {
			diag( $failure );
			}
		}
	};

done_testing();

sub get_rx () {
	my $versions_array = {
		type => '//arr',
		contents => {
			type => '//rec',
			required => {
				date    => { type => '//str', },
				version => { type => '//str', },
				}
			},
		};

	my $advisories_array = {
		type => '//arr',
		contents => {
			type => '//rec',
			required => {
				affected_versions        => { type => '//arr', contents => { type => '//any', of => [ '//str', '//nil' ] } },
				cves                     => { type => '//arr', contents => { type => "tag:example.com,EXAMPLE:rx/cve" }, },
				description              => { type => '//str' },
				distribution             => { type => '//str' },
				fixed_versions           => { type => '//arr', contents => { type => '//any', of => [ '//str', '//nil' ] } },
				id                       => { type => '//str' },
				reported                 => { type => "//any", of => [ 'tag:example.com,EXAMPLE:rx/cpansa-date', '//nil' ] },
				},
			optional => {
				comment => { type => '//any', of => [ '//str', '//nil' ] },
				darkpan => {type => '//str', },
				distributed_version => '//str',
				github_security_advisory => { type => '//arr', contents => { type => '//any' => of => [qw(tag:example.com,EXAMPLE:rx/ghsa //nil)] }, },
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
				previous_id    => { type => '//arr', contents => { type => "//str" }, },
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
				severity    => { type => '//any', of => [ '//str', '//nil' ] },
				'x-commit' => { type => '//any', of => [ '//str', '//nil' ] },
				},
			},
		};

	my $dists_values = {
		type => '//rec',
		required => {
			advisories  => $advisories_array,
			main_module => { type => '//str' },
			versions    => $versions_array,
			},
		};

	my $dists_rx = {
		type   => '//map',
		values => $dists_values,
		};

	my $meta_rx = {
		type     => '//rec',
		required => {
			commit    => { type => 'tag:example.com,EXAMPLE:rx/commit-id' },
			date      => { type => '//str' },
			epoch     => { type => '//num' },
			generator => { type => '//str' },
			repo      => { type => 'tag:example.com,EXAMPLE:rx/vcs-url' },
			},
		};

	my $module2dist_rx = {
		type => '//any',
		};

	my $record = {
	  type     => '//rec',
	  required => {
		meta        => $meta_rx,
		dists       => $dists_rx,
		module2dist => $module2dist_rx,
	  },
	};
}

__END__
