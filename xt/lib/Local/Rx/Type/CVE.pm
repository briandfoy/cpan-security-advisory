=head1 NAME

Local::Rx::Type::CVE - a value looks like a CVE report number

=head1 SYNOPSIS

This is a user-defined type for L<Data::Rx>:

	use Data::Rx;
	use Local::Rx::Type::CVE;

	Data::Rx->new({
		type_plugins => [qw(
			Local::Rx::Type::CVE
			)],
	});

This is automatically loaded in C<Local::Rx>:

	use FindBin qw($RealBin);
	use lib "$RealBin/lib";

	my $rx = Local::Rx->new;

In your Rx specification, use the tag C<tag:example.com,EXAMPLE:rx/cve>:

	my $rx = {
		type => '//rec',
		required => {
			cve => { type => 'tag:example.com,EXAMPLE:rx/cve', },
			},
		...
		};

=head1 DESCRIPTION

This is a user-defined type for L<Data::Rx> that checks that a value
looks like a Common Vulnerabilities and Exposures (CVE) report number.
That's typically the year followed by a dash then a decimal number.

=head1 SEE ALSO

=over 4

=item * L<Data::Rx::CommonType::EasyNew>

=item * L<Data::Rx>

=item * L<https://rx.codesimply.com/>

=item * L<https://www.cve.org>

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
