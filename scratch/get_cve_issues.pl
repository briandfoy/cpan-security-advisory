#!/Users/brian/bin/perl
use v5.26;
use utf8;
use open qw(:std :utf8);
use experimental qw(signatures);

use FindBin;
use lib "$FindBin::Bin/../lib";

use Local::CPANSA qw(:all);

use Mojo::Util qw(dumper);

my $issues = get_github_cve_issues( 'briandfoy', 'z-test-repo' );

my @issue_n;
foreach my $issue ( $issues->@* ) {
	printf "%4d %s\n", map { $issue->{$_} } qw(number title);
	push @issue_n, $issue->{'title'};
	}

push
	@issue_n,
	map { sprintf "CVE-%d-%d", rand(1000), rand(10_000) }
	1 .. 4;

my $opts = {
	owner => 'briandfoy',
	repo  => 'z-test-repo',
	};

my $hash = github_cve_issue_exists( \@issue_n, $opts );
say dumper($hash);
