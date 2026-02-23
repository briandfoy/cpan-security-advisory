use v5.22;

=head1 NAME

Local::Rx::Type::VersionRange - a value looks like a YYYY-MM-DD date

=head1 SYNOPSIS

This is a user-defined type for L<Data::Rx>:

	use Data::Rx;
	use Local::Rx::Type::VersionRange;

	Data::Rx->new({
		type_plugins => [qw(
			Local::Rx::Type::VersionRange
			)],
	});

This is automatically loaded in C<Local::Rx>:

	use FindBin qw($RealBin);
	use lib "$RealBin/lib";

	my $rx = Local::Rx->new;

In your Rx specification, use the tag C<tag:example.com,EXAMPLE:rx/cpansa-version-range>:

	my $rx = {
		type => '//rec',
		required => {
			commit => { type => 'tag:example.com,EXAMPLE:rx/cpansa-version-range', },
			},
		...
		};

=head1 DESCRIPTION

This is a user-defined type for L<Data::Rx> that checks that a value
looks like a version range as used in CPANSA reports.

=head2 Versions


=head1 SEE ALSO

=over 4

=item * L<Data::Rx::CommonType::EasyNew>

=item * L<Data::Rx>

=cut

=head1 SOURCE AVAILABILITY

Although this module may come with your L<CPANSA::DB> distribution,
it is not indexed by PAUSE.

This module is on Github:

	https://github.com/briandfoy/cpan-security-advisories

=head1 AUTHOR

brian d foy, C<< <briandfoy@pobox.com> >>

=head1 COPYRIGHT AND LICENSE

Copyright © 2026, brian d foy C<< <briandfoy@pobox.com> >>. All rights reserved.

This software is available under the Artistic License 2.0.

=cut

package # hide from PAUSE
	Local::Rx::Type::VersionRange;
use parent 'Data::Rx::CommonType::EasyNew';

sub type_uri {
	'tag:example.com,EXAMPLE:rx/cpansa-version-range',
	}

sub assert_valid {
	my ($self, $value) = @_;

	my $op         = qr/ ( [!<>]=? | [<>=]= ) /nx;
	my $version_re = qr/ ( v? \d+ (\.\d+)* (_\d+)? ) /nxa;

	my $pattern    = qr/ \A $op? $version_re (, $op? $version_re )?  \z /nxa;

	$value =~ /$pattern/ or $self->fail({
		error => [ qw(type) ],
		message => "version value ($value) is not recognized",
		value => $value,
		})
	}

__PACKAGE__;
