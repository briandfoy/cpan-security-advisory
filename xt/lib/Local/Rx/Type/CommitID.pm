=head1 NAME

Local::Rx::Type::CommitID - a value looks like a git commit ID

=head1 SYNOPSIS

This is a user-defined type for L<Data::Rx>:

	use Data::Rx;
	use Local::Rx::Type::CommitID;

	Data::Rx->new({
		type_plugins => [qw(
			Local::Rx::Type::CommitID
			)],
	});

This is automatically loaded in C<Local::Rx>:

	use FindBin qw($RealBin);
	use lib "$RealBin/lib";

	my $rx = Local::Rx->new;

In your Rx specification, use the tag C<tag:example.com,EXAMPLE:rx/commit-id>:

	my $rx = {
		type => '//rec',
		required => {
			commit => { type => 'tag:example.com,EXAMPLE:rx/commit-id', },
			},
		...
		};

=head1 DESCRIPTION

This is a user-defined type for L<Data::Rx> that checks that a value
looks like a git commit ID. So far, that's just 40 case-insensitive hex digits.

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

Copyright © 2024-2026, brian d foy C<< <briandfoy@pobox.com> >>. All rights reserved.

This software is available under the Artistic License 2.0.

=cut

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
