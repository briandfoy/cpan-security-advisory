use v5.28; # attributes now come before signature

package Local::CPANSA;
use experimental qw(signatures);

use Carp;
use Exporter qw(import);

our(@EXPORT, @EXPORT_OK, %EXPORT_TAGS);

our %EXPORT_TAGS;
$EXPORT_TAGS{'all'}     = [ @EXPORT, @EXPORT_OK ];
$EXPORT_TAGS{'default'} = [ @EXPORT ];

use Local::Attributes;
use Digest::SHA qw(sha256_hex);
use Mojo::JSON qw(decode_json);
use Mojo::URL;
use Ref::Util qw( is_plain_arrayref is_plain_hashref );

=encoding utf8

=head1 NAME

Local::CPANSA - tools for working within the repo

=head1 SYNOPSIS

	use Local::CPANSA;

=head1 DESCRIPTION

These are all utility functions used across various tools.

Things are kinda a mess as I try to move common behavior from various programs
into this module and figure out how to best organize it. All of this started as
simple functions.

=head2 Advisories

The advisory is all the data we have on a problem. These are mostly about CVE
reports, but they don't need to have a CVE.

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

=back

=head2 CVEs

=over 4

=item * cve_ignored(CVE)

Returns true if the CVE is ignored in cpan-security-advisory. This means that
the report was evaluated to be outside the scope of CPAN, such as non-CPAN
project that uses a Perl module incorrectly, or a report that somehow mentions
Perl but is not a Perl or CPAN issue.

=cut

sub cve_ignored :Export_Ok() :Export_Tag("cve") ( $cve ) {
	state $hash = get_ignored_cves();
	exists $hash->{$cve};
	}

=item * cve_recorded(CVE)

Returns true if the CVE is recorded in cpan-security-advisory.

=cut

use Mojo::Util qw(dumper);
sub cve_recorded :Export_Ok() :Export_Tag("cve") ( $cve ) {
	state $hash = get_recorded_cves();
	$cve = uc($cve);
	# say STDERR "CVE: $cve " . dumper( $hash->{$cve} );
	defined $hash->{$cve} ? $hash->{$cve}[0] : ();
	}

=item * get_all_cve()

Takes the raw CVE search results and reduces it to an array ref of hashes, where
each hash has keys for C<cve>, C<description>, C<url>, C<recorded>, and C<ignored>.

The B<type> key is one of C<reported>, C<ignored>, or C<unevaluated>.

=cut

sub get_all_cve :Export_Ok() :Export_Tag("cve") {
	state $sub_name = (caller(0))[3] =~ s/.*:://r;

	my @results;
	foreach my $v ( get_cve_search_results()->@* ) {
		next unless exists $v->{'cve'};
		my $cve  = $v->{'cve'}{'id'};

		my $url = 'https://nvd.nist.gov/vuln/detail/' . $cve;

		my( $desc ) =
			map {  $_->{'value'} }
			grep { $_->{'lang'} eq 'en' }
			$v->{'cve'}{'descriptions'}->@*;

		my $recorded = cve_recorded($cve);
		my $ignored  = cve_ignored($cve);

		my $type = do {
			   if( $recorded ) { 'recorded'    }
			elsif( $ignored  ) { 'ignored'     }
			else               { 'unevaluated' }
			};

		my @references =
			sort
			map { $_->{'url'} }
			$v->{'cve'}{'references'}->@*;

		my $ghsa;
		my $dist_info = {};
		my $package;
		# say STDERR "$sub_name: CVE: $cve TYPE: $type";
		if( $type eq 'unevaluated' ) {
			# say STDERR "$sub_name: CVE: $cve TYPE: $type FETCHING EXTRA";
			$ghsa = get_github_advisories($cve)->[0];
			$package = guess_package($v);
			# say STDERR "$sub_name: CVE: $cve PACKAGE: $package";
			$dist_info = get_dist_info($package) if $package;
			}

		push @results, {
			cve          => $cve,
			changes      => $dist_info->{'changes'},
			description  => $desc,
			distribution => $dist_info->{'dist_name'},
			ghsa         => $ghsa,
			ignored      => $ignored,
			latest       => $dist_info->{'latest'},
			main_module  => $dist_info->{'main_module'},
			metacpan_link => Mojo::URL->new( "https://metacpan.org/pod/$dist_info->{'main_module'}" ),
			package      => $package,
			recorded     => $recorded,
			references   => \@references,
			type         => $type,
			unevaluated  => !( $ignored or $recorded ),
			url          => $url
			};
		}

	@results =
		map  { $_->[0] }
		sort { $a->[1] <=> $b->[1] or $a->[2] <=> $b->[2] }
		map  { [ $_, $_->{'cve'} =~ /-(\d+)-(\d+)/a ] }
		@results;

	return \@results;
	}

=item * get_cve_data(CVE)

Grab the JSON data for C<CVE> from I<services.nvd.nist.gov>.

=cut

sub get_cve_data ( $cve ) {
	my $search_results = get_cve_search_results();

	foreach my $item ( $search_results->@* ) {
		if( $item->{'cve'}{'id'} eq uc($cve) ) {
			return $item->{'cve'};
			last;
			}
		}

	return {};
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

=item * get_cve_search_results()

Returns the data structure that NIST sent us. We cache this for up to half of
a day. It extracts the C<vulnerabilities> portion and returns that.

The cache file, F<cve-search-results.json>, is at the top-level of the directory.

=cut

sub get_cve_search_results :Export_Ok() :Export_Tag("cve") ( $keyword = 'Perl' ) {
	state $url     = "https://services.nvd.nist.gov/rest/json/cves/2.0";
	state $section = 'data';
	state $tag     = 'cve-search-results.json';

	my $json = get_cache_item( $section, $tag );
	say STDERR "Cache item $section/$tag is undef";

	unless( defined $json ) {
		$json = get_ua()->get($url => form => { keywordSearch => $keyword })->res->json;
		set_cache_item( $section, $tag, $json );
		}

	unless( exists $json->{'vulnerabilities'} ) {
		carp "Problem with the JSON from NIST: Did not have 'vulnerabilities' key";
		return [];
		}

	return $json->{'vulnerabilities'};
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

=item * get_recorded_cves()

Returns a hash reference where the keys are the CVE, and the value is an array
ref of the files it was found in. Typically, there is only one file, but there
are a few odd cases out there.

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

		foreach my $found (@found_cves) {
			push $found{$found}->@*, $file;
			}
		}

	return \%found;
	}

=item * get_unevaluated_cves()

Reduce the list from C<get_all_cve> to just the unevaluated reports.

=cut

sub get_unevaluated_cves :Export_Ok() :Export_Tag("cve") {
	[ grep { $_->{'unevaluated'} } get_all_cve()->@* ]
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

=back

=head2 Reports

=over 4

=item * load_report( PATH )

Load the data for the report and return a Perl hash. Using this means
you never need to know the details about how the report is stored.

=cut

sub load_report :Export_Ok :Export_Tag("reports") ( $report_path ) {
	state $rc = require YAML::XS;
	my $yaml = eval { YAML::XS::LoadFile( $report_path ) };
	}

=item * report_dir

Returns the directory that holds the YAML reports.

=cut

sub report_dir :Export_Ok :Export_Tag("file") () {
	find_root()->child('cpansa')
	}

=item * report_path(PACKAGE)

Return the report path for a given package. If a report path does not
exist, returns the empty list.

=cut

sub report_path ( $package ) {
	use File::Spec::Functions qw(catfile);
	my $try = report_dir()->child( "CPANSA-$package.yml" );
	-e $try ? $try : ()
	}

=item * save_report( PATH, HASHREF )

Save the data for the report.

=cut

sub save_report :Export_Ok :Export_Tag("reports") ( $report_path, $hashref ) {
	state $rc = require YAML::XS;
	eval { YAML::XS::DumpFile( $report_path, $hashref ) };
	}

=back

=head2 CPAN

For these, the C<DIST> argument can be the namespace with double colons (C<Some::Package>)
or the dashed form (C<Some-Package)). The functions will figure it out.

=over 4

=item * get_dist_info( DIST )

Get the distribution info from MetaCPAN. The C<DIST> can use the C<-> (dash) or
the C<::> (double colon). Returns a hash ref of various info.

=cut

sub metacpan_cache ( $method, $args, $sub = sub ($a) { $a->@* } ) {
	state $rc = do {
		unless( eval { require MetaCPAN::Client } ) {
			die <<~'HERE';
				Could not load MetaCPAN::Client. Do you need to install
				it or set PERL5LIB to find it?
				HERE
			}
		};
	state $mcpan = MetaCPAN::Client->new;
	state $section = 'metacpan';

	# say STDERR "metacpan_cache method: $method args: (@$args)";

	my $sha256 = sha256_hex( join "\000", $args->@* );
	my $tag = join '-', $method, $sha256;
	my $contents = get_cache_item( $section, $tag );

	unless( defined $contents ) {
		# say STDERR "metacpan_cache fetching fresh method: $method args: (@$args)";
		$contents = eval { $mcpan->$method( $sub->($args) ) };
		delete $contents->{'client'};
		if( length $@ ) {
			warn "metacpan_cache method: $method args: (@$args) AT: $@\n";
			return;
			}
		set_cache_item( $section, $tag, $contents )
		}

	return $contents;
	}

sub get_dist_info :Export_Ok :Export_Tag("cpan") ( $package_or_dist ) {
	my $dist = eval {
		if( $package_or_dist =~ /::/ or $package_or_dist !~ /-/ ) {
			my $module = metacpan_cache( 'module', [ $package_or_dist ] );
			metacpan_cache( 'distribution', [ $module->distribution ] );
			}
		elsif( $package_or_dist =~ /-/ ) {
			metacpan_cache( 'distribution', [ $package_or_dist ] );
			}
		else {
			();
			}
		};

	return {} unless defined $dist;

	my $latest = metacpan_cache( 'release', [ $dist->name ] );
	my $changes = latest_changes($latest);

	return {
		argument  => $package_or_dist,
		dist_name => $dist->name,
		latest    => $latest->version,
		changes   => $changes,
		main_module => $latest->main_module,
		};
	}

sub latest_changes ($latest) {
	state $section = 'metacpan';
    my @args = ( $latest->author, $latest->name );
	my $tag = join '-', @args, 'changes';
	my $changes = get_cache_item( $section, $tag );
	return my $last = (values $changes->%*)[0] if keys $changes->%*;

    for my $filename (qw(Changes CHANGES ChangeLog Changelog CHANGELOG CHANGELOG.md)) {
        my $url = sprintf 'https://fastapi.metacpan.org/v1/source/%s/%s/%s', @args, $filename;
        my $tx = get_ua()->get($url);
        if( $tx->res->is_success ) {
        	$changes = $tx->res->body;
			set_cache_item( $section, $tag, { $filename => $changes });
 			last;
       		}
    	}

    return $changes;
	}

=item * guess_package(ITEM)

Given the return value of C<assemble_item>, guess what Perl package might be
involved. This looks for clues in the references or descriptions even if it's often
not helpful.

First, if there is a MetaCPAN URL that we recognize, grab the distribution or
package name out of it. If we find that, return it.

Second, if there is an old I<search.cpan.org> URL, do the same thing.

Last, look in the description for things that look like a package name (C<::>)
and return that if found.

Otherwise, return the empty list.

This could be much more sophisticated.

=cut

sub guess_package :Export_Ok :Export_Tag("cpan") ( $item ) {
	my @urls = map { Mojo::URL->new($_->{'url'}) } $item->{'cve'}{'references'}->@*;

	my( $metacpan ) = grep { $_->host =~ /metacpan\.org\z/ } @urls;
	if( defined $metacpan ) {
		return $1 if $metacpan =~ m<https://metacpan.org/(pod|dist)/(.*?)(\z|/)>;
		}

	my( $search ) = grep { $_->host =~ /search\.cpan\.org\z/ } @urls;
	if( defined $search ) {
		say "guess_package: Found a search.cpan.org link <$search>";
		}

	my( $description ) = map { $_->{'value'} }  grep { $_->{'lang'} eq 'en' } $item->{'cve'}{'descriptions'}->@*;
	# say "guess_package: desc: $description";

	if( $description =~ /\b ( [A-Z][A-Z0-9_]+(?:::[A-Z][A-Z0-9_]+)+ ) \b/xi ) {
		# say "guess_package: package: $1";
		return $1
		}

	# say STDERR "guess_package: could not guess a package";
	return;
	}

=back

=head2 Files and Paths

=over 4

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

sub get_all_reports :Export_Ok :Export_Tag("reports") ( $base_dir = report_dir() ) {
	opendir( my $dh, $base_dir ) or die "Could not open <$base_dir>: $!";
	my @files = sort map { catfile $base_dir, $_ } grep ! /\A\./, readdir($dh);
	return \@files;
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

=back

=head2 Cache

=over 4

=item *

=cut

=item * get_cache_dir( SECTION )

=cut

sub get_cache_dir ( $section ) {
	state $dir = do {
		my $d = find_root->child('.cache');
		$d->make_path;
		$d;
		};
	$dir->child($section)->make_path;
	}

=item * get_cache_item( SECTION, TAG, TTL )

=cut

sub get_cache_item ( $section, $tag, $ttl = 0.5 ) {
	state $sub_name = (caller(0))[3] =~ s/.*:://r;

	my $file = get_cache_dir($section)->child($tag);
#	say STDERR "$sub_name: file <$file>";
	return unless -e $file;
	return if -M _ > $ttl;

#	say STDERR "$sub_name: retrieving file <$file>";
	my $contents = eval { Storable::retrieve($file) };

	return do {
		if( $@ ) {
			warn "$sub_name: Could not retrieve file <$file>: $@\n";
			();
			}
		elsif( is_plain_arrayref($contents) and 0 == $contents->@* ) {
			warn "$sub_name: Empty array ref in <$file>. Ignoring.\n";
			();
			}
		elsif( is_plain_hashref($contents) and 0 == keys $contents->%* ) {
			warn "$sub_name: Empty hash ref in <$file>. Ignoring.\n";
			();
			}
		else {
			$contents;
			}
		};
	}

=item * set_cache_item( SECTION, TAG, ITEM )

=cut

sub set_cache_item ( $section, $tag, $item ) {
	my $file = get_cache_dir($section)->child($tag);
#	say STDERR "set_cache_item: file <$file>";
#	say STDERR "set_cache_item: item " . dumper($item);
	Storable::store($item, $file);
	}

=back

=head2 GitHub

Most of these require a GitHub token. See C<get_github_token()>.

=over 4

=item * default_github_owner

Returns C<briandfoy>, the GitHub owner for the GitHub repo.

=item * default_github_repo

Returns C<cpan-security-advisory>, the GitHub repo name.

=cut

sub default_github_owner :Export_Ok() :Export_Tag("github") () { 'briandfoy' }

sub default_github_repo  :Export_Ok() :Export_Tag("github") () { 'cpan-security-advisory' }

=item * get_github_advisories(CVE)

Return an array ref of GitHub Security Advisory IDs associated with C<CVE>.

This will use the token in any of C<CPANSA_GITHUB_TOKEN>, C<GITHUB_TOKEN>, or C<GH_TOKEN>
as reported by C<get_github_token>.

Otherwise this will make an unauthenticated request.

=cut

# https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28#list-global-security-advisories
sub get_github_advisories :Export_Ok() :Export_Tag("github") ( $cve ) {
	state $cache_section = 'ghsa';
	state $url = Mojo::URL->new('https://api.github.com/advisories');

	# this is a shim for old behavior because I don't want accidentally
	# bad input to blow up. Just move on and we can fix it later.
	return [] unless (defined $cve and length $cve);

	$cve = uc($cve);
	$cve = "CVE-$cve" if $cve =~ /\A\d+-\d+\z/a;

	my $json = get_cache_item( $cache_section, $cve );

	unless( defined $json ) {
		my $headers = {
			Accept                 => 'application/vnd.github+json',
			'X-GitHub-Api-Version' => '2026-03-10',
			};
		my $query = {
			cve_id => $cve
			};

		my $token = get_github_token();
		if( $token ) {
			$headers->{'Authorization'} = 'Bearer ' . $token;
			}
		my $tx = get_ua()->get($url => $headers => form => $query);

		unless( $tx->res->is_success ) {
			carp "Could not get GHSA ID: " . $tx->res->body;
			return [];
			}
		$json = $tx->res->json;

		set_cache_item( $cache_section, $cve, $json );
		}

	my $ghsa_ids =  [ map { $_->{'ghsa_id'} } $json->@* ];
	return $ghsa_ids;
	}

=item * get_github_cve_issues( [ OWNER [, REPO] ] )

Return the open issues for the GitHub repository C<OWNER/REPO>. This uses the
default values, and is probably not useful here for any other values.

=cut

sub get_github_cve_issues :Export_Ok() :Export_Tag("github") ( $owner = default_github_owner(), $repo = default_github_repo() ) {
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

sub get_github_token :Export_Ok() :Export_Tag("github") () {
	$ENV{CPANSA_GITHUB_TOKEN} // $ENV{GITHUB_TOKEN} // $ENV{GH_TOKEN}
	}

=item * github_cve_issue_exists( ARRAY_REF, OPTS_HASH_REF )

=cut

sub github_cve_issue_exists :Export_Ok() :Export_Tag("github") ($args, $opts = {}) {
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

=back

=head2 RT

Deal with I<rt.cpan.org>.

=over 4

=item * rt_n_to_url(N)

Returns the I<rt.cpan.org> URL for ticket C<N>.

=cut

sub rt_n_to_url ( $rt ) {
	"https://rt.cpan.org/Public/Bug/Display.html?id=$rt"
	}


=back

=cut

1;
