=head1 NAME

Local::Rx::Type::VCS_URL - a value looks like a URL for a GitHub repo

=head1 SYNOPSIS

This is a user-defined type for L<Data::Rx>:

	use Data::Rx;
	use Local::Rx::Type::VCS_URL;

	Data::Rx->new({
		type_plugins => [qw(
			Local::Rx::Type::VCS_URL
			)],
	});

This is automatically loaded in C<Local::Rx>:

	use FindBin qw($RealBin);
	use lib "$RealBin/lib";

	my $rx = Local::Rx->new;

In your Rx specification, use the tag C<tag:example.com,EXAMPLE:rx/vcs-url>:

	my $rx = {
		type => '//rec',
		required => {
			commit => { type => 'tag:example.com,EXAMPLE:rx/vcs-url', },
			},
		...
		};

=head1 DESCRIPTION

This is a user-defined type for L<Data::Rx> that checks that a value
looks like a source control URL. So far, this is not that sophisticated: it checks
that it starts with a https, git, or svn scheme.

=head1 SEE ALSO

=over 4

=item * L<Data::Rx::CommonType::EasyNew>

=item * L<Data::Rx>

=item * L<https://rx.codesimply.com/>

=cut

=head1 SOURCE AVAILABILITY

Although this module may come with your L<CPANSA::DB> distribution,
it is not indexed by PAUSE.

This module is on Github:

	https://github.com/briandfoy/cpan-security-advisories

=head1 AUTHOR

brian d foy, C<< <briandfoy@pobox.com> >>

=head1 COPYRIGHT AND LICENSE

Copyright © 2024, brian d foy C<< <briandfoy@pobox.com> >>. All rights reserved.
This software is available under the Artistic License 2.0.

=cut

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
