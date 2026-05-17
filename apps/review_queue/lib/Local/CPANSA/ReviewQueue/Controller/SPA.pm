use v5.42;
use utf8;

package Local::CPANSA::ReviewQueue::Controller::SPA;
use Mojo::Base 'Mojolicious::Controller', -signatures;

use lib qw(/Users/brian/Dev/cpan-security-advisory/lib);
use Local::CPANSA qw(:cve);

sub main ($c) {
	my $cves = get_all_cve();

	$c->render(
		template => 'main_spa',
		format   => 'html',
		msg      => 'Welcome to the Mojolicious real-time web framework!',
		cves     => $cves,
		title    => 'CVE Review Queue'
		);
	}

1;
