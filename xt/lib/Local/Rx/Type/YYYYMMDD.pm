package # hide from PAUSE
	Local::Rx::Type::YYYYMMDD;
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

__PACKAGE__;
