=head1 NAME

Local::Rx - a convenient way to load Data::Rx with all the local types

=head1 SYNOPSIS

This is a user-defined type for L<Data::Rx>:

	use FindBin qw($RealBin);
	use lib "$RealBin/lib";

	my $rx = Local::Rx->new;

	... use $rx as you would in Data::Rx ...

=head1 DESCRIPTION

This loads all the local types so you don't have to. These modules
are all in F<xt/lib> so far.

=head2 Types

=over 4

=item * Local::Rx::Type::CommitID

=item * Local::Rx::Type::CVE

=item * Local::Rx::Type::GHSA

=item * Local::Rx::Type::URL

=item * Local::Rx::Type::VCS_URL

=item * Local::Rx::Type::VersionRange

=item * Local::Rx::Type::YYYYMMDD

=back

=head1 SEE ALSO

=over 4

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
	Local::Rx;

use Data::Rx;

use Local::Rx::Type::CommitID;
use Local::Rx::Type::CVE;
use Local::Rx::Type::GHSA;
use Local::Rx::Type::URL;
use Local::Rx::Type::VCS_URL;
use Local::Rx::Type::VersionRange;
use Local::Rx::Type::YYYYMMDD;

sub new {
	Data::Rx->new({
		type_plugins => [ map { "Local::Rx::Type::$_" } qw(
			YYYYMMDD
			GHSA
			CVE
			URL
			VCS_URL
			VersionRange
			CommitID
			)],
	});
	}

__PACKAGE__;
