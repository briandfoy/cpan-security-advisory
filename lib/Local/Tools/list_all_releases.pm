use v5.26;
use utf8;
use experimental qw(signatures);

=head1 NAME

list_all_releases - output the URLs for all releases of a Perl module

=head1 SYNOPSIS

	% perl list_all_releases Git::XS
	https://cpan.metacpan.org/authors/id/I/IN/INGY/Git-XS-0.01.tar.gz
	https://cpan.metacpan.org/authors/id/I/IN/INGY/Git-XS-0.02.tar.gz

	% perl util/list_all_releases Git::XS | \
	    while read i; do curl --silent --remote-name $i; done
	% for f in *.tar.gz; do tar -xzf $f; done

=head1 DESCRIPTION

=over 4

=cut

package Local::Tools::list_all_releases;

__PACKAGE__->run(@ARGV) unless caller;

=item * run

=cut

sub run ( $class, @args ) {
	say join "\n", list_releases($_)->@* for @args;
	}

=item * list_releases( PACAKGE | DIST )

=cut

sub list_releases ( $package_or_dist ) {
	state $rc = do {
		unless( eval { require MetaCPAN::Client } ) {
			die <<~'HERE';
				Could not load MetaCPAN::Client. Do you need to install
				it or set PERL5LIB to find it?
				HERE
			}
		};
	state $mcpan = MetaCPAN::Client->new;

	my $dist = $package_or_dist =~ s/::/-/gr;

	my $query = {
		all => [ { distribution => $dist }, ],
		};

	my $releases = $mcpan->release( $query );

	my @urls;
	while( my $item = $releases->next ) {
		push @urls, $item->download_url;
		}

	return \@urls;
	}

=back

=head1 SOURCE AVAILABILITY

This source is in Github:

	http://github.com/briandfoy/cpan-security-advisory

=head1 AUTHOR

brian d foy, C<< <brian d foy> >>

=head1 COPYRIGHT AND LICENSE

Copyright © 2022, brian d foy, All Rights Reserved.

You may redistribute this under the terms of the Artistic License 2.0.

=cut
__PACKAGE__;
