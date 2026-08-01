use v5.42;
use utf8;

package Local::CPANSA::ReviewQueue::Controller::SPA;
use Mojo::Base 'Mojolicious::Controller', -signatures;

use lib qw(/Users/brian/Dev/cpan-security-advisory/lib);
use lib qw(/Users/brian/Dev/cpan-security-advisory/util/lib);
use Local::Config::make_record;
use Local::CPANSA qw(:cve :file :reports);

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

sub submit ($c) {
	my %hash;

	my $all = $c->add_advisory;

	$c->stash( cve => {
		cve         => $all->{'advisory'}{'cves'}[0],
		recorded    => $all->{'extra'}{'report_path'},
		description => $all->{'advisory'}{'description'},
		type        => 'recorded',
		main_module => $all->{'extra'}{'main_module'},
		});
	$c->render(
		template => 'partials/list-item',
		format   => 'html',
		);
	}

sub guess_output_filename ( $namespace ) {
	state $root = do {
		require File::FindRoot;
		File::FindRoot->dir_contains( 'cpansa' );
		};

	my $basename = sprintf 'CPANSA-%s.yml', $namespace =~ s/::/-/gr;
	return catfile($root, $basename);
	}

sub add_advisory ($c) {
	my %advisory;
	my %extra;

	$extra{'main_module'} = $c->param('main_module');
	$extra{'distribution'} = $c->param('distribution');

	$c->app->log->debug( "add_advisory: distribution is <$extra{'distribution'}>" );
	my $cve_details = get_cve_data( $c->param('cve') );

	$extra{'report_path'} = "" . Local::CPANSA::report_path( $c->param('distribution') );

	$advisory{'cves'}                     = [ $c->param('cve') ];
	$advisory{'id'}                       = sprintf( 'CPANSA-%s-%s', $extra{'distribution'}, $advisory{'cves'}[0] =~ s/CVE-//r ),
	$advisory{'description'}              = $c->param('description');
	$advisory{'references'}               = [ map { $_->{'url'} } $cve_details->{'references'}->@* ];
	$advisory{'reported'}                 = $cve_details->{'published'} =~ s/T.*//r;;
	$advisory{'severity'}                 = eval { lc $cve_details->{'metrics'}{'cvssMetricV31'}[0]{'cvssData'}{'baseSeverity'} };
	$advisory{'affected_versions'}        = [ $c->param('affected-versions') ];
	$advisory{'fixed_versions'}           = [ $c->param('fixed-versions') ];
	$advisory{'github_security_advisory'} = [ $c->param('ghsa-id') ];

	$c->app->log->debug( "add_advisory: Hash: " . dumper(\%advisory) );

	my $data = load_report($extra{'report_path'});
	$data = new_meta($extra{'main_module'}) unless $data;

	push $data->{'advisories'}->@*, \%advisory;

	$c->app->log->debug( "DATA: " . Mojo::Util::dumper($data) );


	$c->app->log->debug( "add_advisory: Data: " . dumper($data) );

	save_report( $extra{'report_path'}, $data );

	return {
		advisory => \%advisory,
		data     => $data,
		extra    => \%extra,
		};

	}

sub new_meta ( $namespace ) {
	my %hash;

	my( $package, $dist, $latest_version, $repo ) = do {
		if( $namespace eq 'perl' ) {
			( 'perl', 'perl', undef, 'https://github.com/Perl/perl5' )
			}
		else {
			state $rc = require MetaCPAN::Client;
			my( $package, $dist_name, $version, $repo );
			eval {
				my $mcpan = MetaCPAN::Client->new;
				my $package = $mcpan->package($namespace);
				$version = $package->version;
				my $dist = $mcpan->distribution($package->distribution);
				$dist_name = $dist->name;
				$repo = eval { $dist->github->{source} } if keys $dist->github->%*;
				};
			($package, $dist_name, $version, $repo );
			}
		};

	$hash{cpansa_version} = 2;
	$hash{darkpan}        = undef;
	$hash{distribution}   = $dist;
	$hash{last_checked}   = time;
	$hash{latest_version} = $latest_version;
	$hash{metacpan} = "https://metacpan.org/pod/" . $namespace;
	$hash{advisories} = [];

	\%hash;
	}

sub dumper { state $rc = require Data::Dumper; Data::Dumper->new([@_])->Indent(1)->Sortkeys(1)->Terse(1)->Useqq(1)->Dump }

1;
