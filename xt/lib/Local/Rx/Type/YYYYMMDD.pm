=head1 NAME

Local::Rx::Type::YYYYMMDD - a value looks like a YYYY-MM-DD date

=head1 SYNOPSIS

This is a user-defined type for L<Data::Rx>:

	use Data::Rx;
	use Local::Rx::Type::YYYYMMDD;

	Data::Rx->new({
		type_plugins => [qw(
			Local::Rx::Type::YYYYMMDD
			)],
	});

This is automatically loaded in C<Local::Rx>:

	use FindBin qw($RealBin);
	use lib "$RealBin/lib";

	my $rx = Local::Rx->new;

In your Rx specification, use the tag C<tag:example.com,EXAMPLE:rx/cpansa-date>:

	my $rx = {
		type => '//rec',
		required => {
			commit => { type => 'tag:example.com,EXAMPLE:rx/cpansa-date', },
			},
		...
		};

=head1 DESCRIPTION

This is a user-defined type for L<Data::Rx> that checks that a value
looks like a date as used in CPANSA reports, which use the YYYY-MM-DD
format (even though the dashes can't appear in a Perl package name).
This does not verify that the date is valid.

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

Copyright © 2024-2026, brian d foy C<< <briandfoy@pobox.com> >>. All rights reserved.

This software is available under the Artistic License 2.0.

=cut

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
