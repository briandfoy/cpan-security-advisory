=head1 NAME

Local::Rx::Type::GHSA - a value looks like a GitHub Advisory Database ID

=head1 SYNOPSIS

This is a user-defined type for L<Data::Rx>:

	use Data::Rx;
	use Local::Rx::Type::GHSA;

	Data::Rx->new({
		type_plugins => [qw(
			Local::Rx::Type::GHSA
			)],
	});

This is automatically loaded in C<Local::Rx>:

	use FindBin qw($RealBin);
	use lib "$RealBin/lib";

	my $rx = Local::Rx->new;

In your Rx specification, use the tag C<tag:example.com,EXAMPLE:rx/ghsa>:

	my $rx = {
		type => '//rec',
		required => {
			commit => { type => 'tag:example.com,EXAMPLE:rx/ghsa', },
			},
		...
		};

=head1 DESCRIPTION

This is a user-defined type for L<Data::Rx> that checks that a value
looks like a GitHub Advisory Database ID, such as C<GHSA-hm5v-6984-hfqp>.

=head1 SEE ALSO

=over 4

=item * L<Data::Rx::CommonType::EasyNew>

=item * L<Data::Rx>

=item * L<https://rx.codesimply.com/>

=item * L<https://github.com/advisories>

=cut

=head1 SOURCE AVAILABILITY

Although this module may come with your L<CPANSA::DB> distribution,
it is not indexed by PAUSE.

This module is on Github:

	https://github.com/briandfoy/cpan-security-advisories

=head1 AUTHOR

brian d foy, C<< <briandfoy@pobox.com> >>

=head1 COPYRIGHT AND LICENSE

Copyright © 2024-2026, brian d foy C<< <briandfoy@pobox.com> >>. All rights reserved.

This software is available under the Artistic License 2.0.

=cut

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
