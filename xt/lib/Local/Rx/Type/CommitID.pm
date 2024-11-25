package # hide from PAUSE
	Local::Rx::Type::CommitID;
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

__PACKAGE__;
