package Local::CPANSA;
use v5.26;
use experimental qw(signatures);

use Exporter qw(import);

our @EXPORT = qw(
	);

our @EXPORT_OK = qw(
	get_all_reports
	get_dist_info
	latest_on_cpan
	load_report
	);

our %EXPORT_TAGS = (
	all => \@EXPORT_OK,
	cpan    => [qw(
		latest_on_cpan
		get_dist_info
		)],
	default => \@EXPORT,
	reports => [qw(
		get_all_reports
		load_report
		)],
	);

=encoding utf8

=head1 NAME

Local::CPANSA - tools for working within the repo

=head1 SYNOPSIS

=head1 DESCRIPTION

=over 4

=cut

=item * assemble_advisory

=cut

sub assemble_advisory ( $config ) {
	my %hash;
	$hash{cves} = [];
	push $hash{cves}->@*, $config->cve if $config->cve;

	my $serial = $hash{cves}[0] =~ s/\ACVE-//r;
	$serial //= sprintf '%s-%s', (localtime)[5] + 1900, '001';

	$hash{description} = undef;
	$hash{references} = [];
	$hash{reported} = undef;
	$hash{severity} = undef;
	$hash{github_security_advisory} = [];
	$hash{affected_versions} = [];
	$hash{fixed_versions} =  [];

	if( $hash{cves}->@* ) {
		my $item = get_cve_data($hash{cves}[0]);
		$hash{description}  = (map { $_->{value} } grep { $_->{lang} eq 'en' } $item->{descriptions}->@* )[0] // '';
		$hash{description}  =~ s/\v/ /g;

		my @references = map { $_->{url} } $item->{references}->@*;
		$hash{references} = \@references;

		$hash{reported} = $item->{published} =~ s/T.*//r;

		$hash{severity} = eval { lc $item->{metrics}{cvssMetricV31}{cvssData}{baseSeverity} } || undef;

		push $hash{github_security_advisory}->@*,
			grep { defined }
			map { get_github_advisories($_)->@* }
			$hash{cves}->@*;
		}

#	my $package = guess_package( $item );
#	$package =~ s/::/-/g;

	my $meta = Local::Config::make_record->new_meta($config);

	$hash{id} = sprintf 'CPANSA-%s-%s', $meta->{distribution}, $serial;

	$hash{embedded_vulnerability} = { name => undef, distributed_version => undef };

	unshift $hash{references}->@*, rt_n_to_url($config->rt) if $config->rt;

	push $hash{affected_versions}->@*,  $config->affected if $config->affected;
	push $hash{fixed_versions}->@*,  $config->fixed if $config->fixed;

	$hash{embedded_vulnerability}{distributed_version} //= $config->embedded_version;
	$hash{embedded_vulnerability}{name}                //= $config->embedded_name;

	delete $hash{embedded_vulnerability} unless(
		defined $config->embedded_version or defined $config->embedded_name
		);

	return \%hash
	}

=item * cve_ignored

=cut

sub cve_ignored ( $cve ) {
	state $hash = get_ignored_cves();
	exists $hash->{$cve};
	}

=item * cve_recorded

=cut

sub cve_recorded ( $cve ) {
	state $hash = get_recorded_cves();
	exists $hash->{$cve};
	}

=item * get_dist_info( DIST )

=cut

sub get_dist_info ( $package_or_dist ) {
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
	my $total = $releases->total;

	my @items;
	while( my $item = $releases->next ) {
		push @items, $item;
		}
	Dumper(\@items); use Data::Dumper;
	return \@items;
	}

=item * guess_package

=cut

sub guess_package ( $item ) {
	my @urls = map { Mojo::URL->new($_->{url}) } $item->{cve}{references}{reference_data}->@*;

	my( $metacpan ) = grep { $_->host =~ /metacpan\.org\z/ } @urls;
	if( defined $metacpan ) {
		return $1 if $metacpan =~ m<https://metacpan.org/(pod|dist)/(.*?)(\z|/)>;
		}

	my( $search ) = grep { $_->host =~ /search\.cpan\.org\z/ } @urls;
	if( defined $search ) {
		say "SEARCH: $search";
		}

	if( $item->{cve}{description}{description_data}[0]{value} =~ /\b ( [A-Z][A-Z0-9_]+(?:::[A-Z][A-Z0-9_]+)+ ) \b/xi ) {
		return $1
		}
	}

=item * parse_cpe23uri

=cut

# This hasn't turned out so useful
sub parse_cpe23uri ( $cpe23uri ) {
	state $keys = [ qw(
		prefix
		version
		part
		vendor
		product
		version
		update
		edition
		language
		sw_edition
		target_sw
		target_hw
		other
		) ];

	state $pattern = qr{  # colons not escaped
		(?<!
			\\
		)
		:
		}x;

	my %hash;
	@hash{$keys->@*} = map { s|\\||gr } split /$pattern/, $cpe23uri;
	return \%hash;
	}

=item * report_path(PACKAGE)

Return the report path for a given package. If a report path does not
exist, returns the empty list.

=cut

sub report_path ( $package ) {
	use File::Spec::Functions qw(catfile);
	my $try = catfile( 'cpansa', "CPANSA-$package.yml" );
	-e $try ? $try : ()
	}

=item * get_all_reports

Returns an arrayref of paths for every CPANSA report.

=cut

sub get_all_reports ( $base_dir = 'cpansa' ) {
	opendir( my $dh, $base_dir ) or die "Could not open <$base_dir>: $!";
	my @files = sort map { catfile $base_dir, $_ } grep ! /\A\./, readdir($dh);
	return \@files;
	}

=item * get_cve_data

=cut

sub get_cve_data ( $cve ) {
	state $rc = require Mojo::URL;
	state $base = Mojo::URL->new('https://services.nvd.nist.gov/rest/json/cves/2.0');
	return {} unless $cve;

	my $url = $base->clone->query( cveId => $cve );
	get_ua()->get($url)->result->json->{vulnerabilities}[0]{cve};
	}

=item * get_cve_description

=cut

sub get_cve_description ( $cve ) {
	my $item = get_cve_data($cve);

	my( $desc ) =
		map { $_->{value} }
		grep { $_->{lang} eq 'en' }
		$item->{descriptions}->@*;

	$desc
	}

=item * get_github_advisories

=cut

# https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28#list-global-security-advisories
sub get_github_advisories ( $cve ) {
	state $rc = require Mojo::UserAgent;

	$cve = uc($cve);
	$cve = "CVE-$cve" if $cve =~ /\A\d+-\d+\z/a;

	my $url = Mojo::URL->new('https://api.github.com/advisories');
	my $headers = {
		Authorization          => join( ' ', 'token', get_github_token() ),
		Accept                 => 'application/vnd.github+json',
		'X-GitHub-Api-Version' => '2022-11-28',
		};
	my $query = {
		cve_id => $cve
		};

	my $tx = get_ua()->get(
		$url => $headers => form => $query
		);

	return [] unless $tx->res->is_success;

	my $ghsa_ids =  [ map { $_->{ghsa_id} } $tx->res->json->@* ];
	}

=item * get_github_token

=cut

sub get_github_token () {
	$ENV{CPANSA_GITHUB_TOKEN}
	}

=item * get_ignored_cves

=cut

sub get_ignored_cves ( $file = 'IGNORE_CVEs' ) {
	open my $fh, '<:encoding(UTF-8)', $file or do {
		warn "Could not open <$file>: $! - Skipping ignored CVEs\n";
		return {};
		};

	my %found;
	while( <$fh> ) {
		next if $file =~ /\A\s*(?:#|\z)/;
		my( $cve ) = split;
		$found{$cve}++;
		}

	return \%found;
	}

=item * get_recorded_cves

=cut

sub get_recorded_cves ( $base = 'cpansa' ) {
	opendir( my $dh, $base ) or die "Could not open <$base>: $!";

	my %found;
	while( my $file = readdir($dh) ) {
		next unless $file =~ /\.yml\z/;
		my $path = catfile( $base, $file );
		my $yaml = load_report($path);

		unless( defined $yaml ) {
			warn "$path: $@\n";
			next;
			}

		my @found_cves =
			map {
				ref $_->{cves} ? $_->{cves}->@* : do {
					warn "$path cves was not an array ref";
					() }
				}
			grep { exists $_->{cves} }
			$yaml->{advisories}->@*;

		@found{@found_cves} = (1)x@found_cves;
		}

	return \%found;
	}

=item * get_ua

=cut

sub get_ua () {
	state $rc = require Mojo::UserAgent;
	state $ua = do {
		my $ua = Mojo::UserAgent->new;
		$ua->max_redirects(3);
		$ua;
		};

	$ua
	};

=item * latest_on_cpan( DIST )

Returns the latest version on CPAN.

=cut

sub latest_on_cpan ($dist) {
	my $d = get_dist_info($dist);
	my($latest) = grep { $_->status eq 'latest' } $d->@*;
	defined $latest ? $latest->version : undef;
	}

=item * load_report( PATH )

Load the data for the report and return a Perl hash. Using this means
you never need to know the details about how the report is stored.

=cut

sub load_report ( $report_path ) {
	state $rc = require YAML::XS;
	my $yaml = eval { YAML::XS::LoadFile( $report_path ) };
	}

=back

=cut

1;
