use v5.36;

use Test::More;

use Data::Rx;
use Mojo::Util;
use YAML::XS;


package CPAN::Audit::DB::Type::YYYYMMDD {
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

package CPAN::Audit::DB::Type::GHSA {
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

package CPAN::Audit::DB::Type::CVE {
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

package CPAN::Audit::DB::Type::URL {
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

package CPAN::Audit::DB::Type::VCS_URL {
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

my @files = glob("cpansa/*.yml");

my $rx = Data::Rx->new({
  type_plugins => [qw(
    CPAN::Audit::DB::Type::YYYYMMDD
    CPAN::Audit::DB::Type::GHSA
    CPAN::Audit::DB::Type::CVE
    CPAN::Audit::DB::Type::URL
	CPAN::Audit::DB::Type::VCS_URL
  )],	});


my $advisories = {
	type => '//arr',
	contents => {
		type => '//rec',
		required => {
			affected_versions        => { type => '//any', of => [ '//str', '//nil' ] },
			cves                     => { type => '//arr', contents => { type => "tag:example.com,EXAMPLE:rx/cve" }, },
			description              => { type => '//str' },
			fixed_versions           => { type => '//any', of => [ '//str', '//nil' ] },
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

my $schema = $rx->make_schema($record);

foreach my $file ( sort @files ) {
	subtest $file => sub {
		my $data = eval { YAML::XS::LoadFile( $file ) };
		ok defined $data, "Loaded YAML data";
		# diag( Mojo::Util::dumper($data) );
		isa_ok $data, ref {};

		eval { $schema->assert_valid($data) };
		my $at = $@;
		if( ! ref $at ) {
			pass "Data for <$file> was valid";
			}
		else {
			fail( "Data for <$file> was not valid" );
			foreach my $failure ( $at->failures->@* ) {
				diag( $failure );
				}
			}
		};
	};

done_testing();

__END__
Failed //rec: found unexpected entries: advisories cpansa_version distribution last_checked latest_version metacpan repo (error: unexpected at $data)
Failed //rec: no value given for required entry location (error: missing at $data)
Failed //rec: no value given for required entry status (error: missing at $data)
