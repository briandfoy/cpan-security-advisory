package # hide from PAUSE
	Local::Rx::Type::GHSA;
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

__PACKAGE__;
