package # hide from PAUSE
	Local::Rx::Type::VCS_URL;
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

__PACKAGE__;
