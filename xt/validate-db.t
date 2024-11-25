use Test::More;

use Data::Rx;
use YAML::XS;

my $class = CPANSA::DB;

subtest sanity => sub {
	use_ok $class or BAIL_OUT( "$class did not compile" );
	can_ok $class, 'db';
	};

package CPANSA::DB::Type::GHSA {
	use parent 'Data::Rx::CommonType::EasyNew';

	sub type_uri {
		'tag:example.com,EXAMPLE:rx/ghsa',
		}

	sub assert_valid { # GHSA-6wjc-jvcr-hcxw
		my ($self, $value) = @_;
		$value =~ /\AGHSA(?:-[a-z0-9]{4}){3}\z/a or $self->fail({
			error => [ qw(type) ],
			message => "value <$value> is not a valid GitHub Advisory Database identifier",
			value => $value,
			})
		}
	}

package CPANSA::DB::Type::VCS_URL {
	use parent 'Data::Rx::CommonType::EasyNew';

	sub type_uri {
		'tag:example.com,EXAMPLE:rx/vcs-url',
		}

	sub assert_valid {
		my ($self, $value) = @_;
		if( ! defined $value ) {
			return $self->fail({
				error => [ qw(type) ],
				message => "URL value is not defined",
				value => $value,
				})
			}
		elsif( $value !~ m{\A(?:https?|git|svn)://}ia ) {
			$self->fail({
				error => [ qw(type) ],
				message => "URL value <$value> is not valid",
				value => $value,
				})
			}
		return 1;
		}
	}

package CPANSA::DB::Type::CommitID {
	use parent 'Data::Rx::CommonType::EasyNew';

	sub type_uri {
		'tag:example.com,EXAMPLE:rx/commit-id',
		}

	sub assert_valid {
		my ($self, $value) = @_;
		if( ! defined $value ) {
			return $self->fail({
				error => [ qw(type) ],
				message => "URL value is not defined",
				value => $value,
				})
			}
		elsif( $value !~ m{\A[\da-f]{40}\z}ia ) {
			$self->fail({
				error => [ qw(type) ],
				message => "Commit ID <$value> is not 40 hexadecimal characters",
				value => $value,
				})
			}
		return 1;
		}
	}

package CPANSA::DB::Type::YYYYMMDD {
	use parent 'Data::Rx::CommonType::EasyNew';

	sub type_uri {
		'tag:example.com,EXAMPLE:rx/cpansa-date',
		}

	sub assert_valid {
		my ($self, $value) = @_;
		return 1 unless defined $value;
		$value =~ /\A(?:19[6789]\d|20[012]\d)-\d\d-\d\d\z/a or $self->fail({
			error => [ qw(type) ],
			message => "date value is not YYYY-MM-DD",
			value => $value,
			})
		}
	}

package CPANSA::DB::Type::CVE {
	use parent 'Data::Rx::CommonType::EasyNew';

	sub type_uri {
		'tag:example.com,EXAMPLE:rx/cve',
		}

	sub assert_valid {
		my ($self, $value) = @_;
		$value =~ /\ACVE-\d+-\d+\z/a or $self->fail({
			error => [ qw(type) ],
			message => "value <$value> is not a valid CVE identifier",
			value => $value,
			})
		}
	}

package CPANSA::DB::Type::URL {
	use parent 'Data::Rx::CommonType::EasyNew';

	sub type_uri {
		'tag:example.com,EXAMPLE:rx/url',
		}

	sub assert_valid {
		my ($self, $value) = @_;
		if( ! defined $value ) {
			return $self->fail({
				error => [ qw(type) ],
				message => "URL value is not defined",
				value => $value,
				})
			}
		elsif( $value !~ m{\A(?:https?|ftp)://}ia ) {
			$self->fail({
				error => [ qw(type) ],
				message => "URL value <$value> is not valid",
				value => $value,
				})
			}
		return 1;
		}
	}

my $rx = Data::Rx->new({
	type_plugins => [qw(
		CPANSA::DB::Type::CommitID
		CPANSA::DB::Type::VCS_URL
		CPANSA::DB::Type::GHSA
		CPANSA::DB::Type::YYYYMMDD
		CPANSA::DB::Type::CVE
		CPANSA::DB::Type::URL
	)],
	});


my $record2 = {
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

my $schema = $rx->make_schema($record);

eval { $schema->assert_valid($class->db) };
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

done_testing();

__END__
