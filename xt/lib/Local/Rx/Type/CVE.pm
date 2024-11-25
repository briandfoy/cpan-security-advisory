package # hide from PAUSE
	Local::Rx::Type::CVE;
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

__PACKAGE__;
