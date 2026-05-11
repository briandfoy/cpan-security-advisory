package Local::CPANSA;
use v5.26;
use experimental qw(signatures);

use Carp;
use Exporter qw(import);

our(@EXPORT, @EXPORT_OK, %EXPORT_TAGS);

our %EXPORT_TAGS;
$EXPORT_TAGS{'all'}     = [ @EXPORT, @EXPORT_OK ];
$EXPORT_TAGS{'default'} = [ @EXPORT ];

use Local::Attributes;

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

=item * cve_ignored(CVE)

Returns true if the CVE is ignored in cpan-security-advisory. This means that
the report was evaluated to be outside the scope of CPAN, such as non-CPAN
project that uses a Perl module incorrectly, or a report that somehow mentions
Perl but is not a Perl or CPAN issue.

=cut

sub cve_ignored ( $cve ) {
	state $hash = get_ignored_cves();
	exists $hash->{$cve};
	}

=item * cve_recorded

Returns true if the CVE is recorded in cpan-security-advisory.

=cut

sub cve_recorded ( $cve ) {
	state $hash = get_recorded_cves();
	exists $hash->{$cve};
	}

=item * default_github_owner

Returns C<briandfoy>, the GitHub owner for the GitHub repo.

=item * default_github_repo

Returns C<cpan-security-advisory>, the GitHub repo name.

=cut

sub default_github_owner () { 'briandfoy' }
sub default_github_repo  () { 'cpan-security-advisory' }

=item * get_dist_info( DIST )

Get the distribution info from MetaCPAN. The C<DIST> can use the C<-> (dash) or
the C<::> (double colon).

=cut

sub get_dist_info :Export_Ok :Export_Tag("cpan") ( $package_or_dist ) {
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

=item * get_all_cve()

Takes the raw CVE search results and reduces it to an array ref of hashes, where
each hash has keys for C<cve>, C<description>, C<url>, C<recorded>, and C<ignored>.

=cut

sub get_all_cve :Export_Ok() :Export_Tag("cve") {
	my @results;
	foreach my $v ( get_cve_search_results()->@* ) {
		next unless exists $v->{cve};
		my $cve  = $v->{cve}{id};

		my( $desc ) =
			map { substr( $_-> {'value'}, 0, 75 ) =~ s/\v+/ /gr }
			grep { $_->{'lang'} eq 'en' }
			$v->{cve}{descriptions}->@*;

		my $url = 'https://nvd.nist.gov/vuln/detail/' . $cve;

		push @results, {
			cve         => $cve,
			description => $desc,
			ignored     => cve_ignored($cve),
			recorded    => cve_recorded($cve),
			unevaluated => !( cve_ignored($cve) or cve_recorded($cve) ),
			url         => $url
			};
		}

	@results =
		map  { $_->[0] }
		sort { $a->[1] <=> $b->[1] or $a->[2] <=> $b->[2] }
		map  { [ $_, $_->{'cve'} =~ /-(\d+)-(\d+)/a ] }
		@results;

	return \@results;
	}

=item * get_unevaluated_cve()

=cut

sub get_unevaluated_cve :Export_Ok() :Export_Tag("cve") {
	[ grep { $_->{'unevaluated'} } get_all_cve()->@* ]
	}

sub get_cve_search_results :Export_Ok() :Export_Tag("cve") ( $keyword = 'Perl' ) {
	my $url = "https://services.nvd.nist.gov/rest/json/cves/2.0";
	my $json = get_ua()
		->get( $url, form => { keywordSearch => $keyword } )
		->res
		->json;

	unless( exists $json->{'vulnerabilities'} ) {
		carp "Problem with the JSON from NIST: Did not have 'vulnerabilities' key";
		return [];
		}

	return $json->{'vulnerabilities'};
	}

=item * guess_package(ITEM)

Given the return value of C<assemble_item>, guess what Perl package might be
involved. This looks for clues in the references or descriptions. It's often
not helpful.

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

Turns the cpe23uri into a hash with proper keys. Although this is here, it hasn't
turned out to be that useful.

=cut

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

=item * get_file_path( REL_PATH )

Find the full path to C<REL_PATH> under the repository root (from C<find_root>).
There might be multiple paths to the same C<REL_PATH>, so this returns an array
ref for every matching path this finds. If it finds no files, the array ref
is empty.

The array is ordered by the most shallow files first (fewest subdirectories) and
alphabetical for two paths at the same level.

=cut


sub get_file_path :Export_Ok :Export_Tag("file") ($rel_path) {
	state $rc = require File::Find;

	my @found = ();
	my $wanted = sub {
		return unless -d $File::Find::name;

		my $candidate = catfile($File::Find::name, $rel_path);
		return unless -e $candidate;

		push @found, $candidate;
		};
	File::Find::find( $wanted, find_root() );

	@found =
		map  { $_->[0] }
		sort { $a->[1] <=> $b->[1] or $a->[0] cmp $b->[0] }
		map  {
			[ $_, scalar Mojo::File->new($_)->to_array->@* ]
			}
		@found;

	return \@found;
	}

=item * find_root( [ STARTING_FILE [, TARGET] ] )

Attempt to find the top level of the repo starting from C<STARTING_FILE>. By
default, it does this by looking for the first directory with a F<Makefile.PL>
directory, but you can choose the target in the optional second argument.

If you don't specify C<STARTING_FILE>, it uses the path to this module. Since
all of these files are expected to be inside the repo, it doesn't matter where we
start.

This remembers the right path for the rest of the lifetime of the program
and always returns that same value.

=cut

sub find_root :Export_Ok :Export_Tag("file") ( $file = __FILE__, $target = 'Makefile.PL' ) {
	state $rc = require Mojo::File;
	state $root;
	return $root if defined $root;

    my $dir = Mojo::File->new(__FILE__)->to_abs->dirname;

    while(1) {

    	if( -e $dir->child($target) ) {
    		$root = $dir;
    		return $root;
    		}
    	last if $dir eq $dir->dirname; # got to root
        $dir = $dir->dirname;
    	}

    return;
	}

=item * get_all_reports

Returns an arrayref of paths for every CPANSA report.

=cut

sub get_all_reports :Export_Ok :Export_Tag("reports") ( $base_dir = 'cpansa' ) {
	opendir( my $dh, $base_dir ) or die "Could not open <$base_dir>: $!";
	my @files = sort map { catfile $base_dir, $_ } grep ! /\A\./, readdir($dh);
	return \@files;
	}

=item * get_cve_data(CVE)

Grab the JSON data for C<CVE> from I<services.nvd.nist.gov>.

=cut

sub get_cve_data ( $cve ) {
	state $rc = require Mojo::URL;
	state $base = Mojo::URL->new('https://services.nvd.nist.gov/rest/json/cves/2.0');
	return {} unless $cve;

	my $url = $base->clone->query( cveId => $cve );
	get_ua()->get($url)->result->json->{vulnerabilities}[0]{cve};
	}

=item * get_cve_description(CVE)

Extract the description for C<CVE>.

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

	unless( $tx->res->is_success ) {
		warn "Could not get GHSA ID: " . $tx->res->body;
		return [];
		}

	my $ghsa_ids =  [ map { $_->{ghsa_id} } $tx->res->json->@* ];
	}

=item * get_github_cve_issues( [ OWNER [, REPO] ] )

=cut

sub get_github_cve_issues ( $owner = default_github_owner(), $repo = default_github_repo() ) {
	my $url = "https://api.github.com/repos/$owner/$repo/issues?state=open";

	my $tx = get_ua()->get($url);

	my @results;

	if( $tx->res->is_success ) {
		foreach my $i ( $tx->res->json->@* ) {
			next unless $i->{title} =~ /\A CVE - \d+ - \d+ \z /ax;
			push @results, $i;
			}
		}

	return \@results;
	}

=item * get_github_token

Returns the value of the CPANSA_GITHUB_TOKEN or GITHUB_TOKEN environment variable.

=cut

sub get_github_token () {
	$ENV{CPANSA_GITHUB_TOKEN} // $ENV{GITHUB_TOKEN}
	}

=item * get_ignored_cves( [PATH] )

Loads the data in the ignored CVE file, which is a whitespace-separated
list of CVE number (i.e. C<CVE-2026-1234>) and a short description. This
returns a hash ref where the keys are the CVE number and the values is
meaningless:

	my $ignored = get_ignored_cves();
	foreach my $cve ( @cves ) {
		next if $ignored->{$cve};
		...
		}

This is mostly useful to check if a particular CVE has already been evaluated
and judged to be outside our scope.

The optional argument is the path to that file. By default, this is the file
F<IGNORED_CVEs> under the repository root.

=cut

sub get_ignored_cves :Export_Ok() :Export_Tag("cve") ( $file = get_file_path('IGNORE_CVEs')->[0] ) {
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

sub get_recorded_cves :Export_Ok() :Export_Tag("cve") ( $base = get_file_path('cpansa')->[0] ) {
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

=item * github_cve_issue_exists( ARRAY_REF, OPTS_HASH_REF )

=cut

sub github_cve_issue_exists ($args, $opts = {}) {
	$opts->%* = (owner => default_github_owner(), repo => default_github_repo(), $opts->%* );
	my( $owner, $repo ) = $opts->@{qw(owner repo)};
	my $issues = get_github_cve_issues( $owner, $repo );
	my %reported =
		map { $_->{title}, $_->{number} }
		grep { $_->{title} =~ /\A CVE - \d+ - \d+ \z/xa }
		$issues->@*;

	my %hash;
	foreach my $cve ( $args->@* ) {
		$hash{$cve} = $reported{$cve};
		}

	return \%hash;
	}

=item * latest_on_cpan( DIST )

Returns the latest version on CPAN.

=cut

sub latest_on_cpan :Export_Ok :Export_Tag("cpan") ($dist) {
	my $d = get_dist_info($dist);
	my($latest) = grep { $_->status eq 'latest' } $d->@*;
	defined $latest ? $latest->version : undef;
	}

=item * load_report( PATH )

Load the data for the report and return a Perl hash. Using this means
you never need to know the details about how the report is stored.

=cut

sub load_report :Export_Ok :Export_Tag("reports") ( $report_path ) {
	state $rc = require YAML::XS;
	my $yaml = eval { YAML::XS::LoadFile( $report_path ) };
	}

=item * rt_n_to_url(N)

Returns the I<rt.cpan.org> URL for ticket C<N>.

=cut

sub rt_n_to_url ( $rt ) {
	"https://rt.cpan.org/Public/Bug/Display.html?id=$rt"
	}

=item * save_report( PATH, HASHREF )

Save the data for the report.

=cut

sub save_report :Export_Ok :Export_Tag("reports") ( $report_path, $hashref ) {
	state $rc = require YAML::XS;
	eval { YAML::XS::DumpFile( $report_path, $hashref ) };
	}

=back

=cut

1;
