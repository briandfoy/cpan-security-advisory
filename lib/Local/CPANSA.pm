package Local::CPANSA;
use v5.26;
use experimental qw(signatures);

sub assemble_record ( $cve, $distribution = undef ) {
	state $base = 'https://services.nvd.nist.gov/rest/json/cve/1.0';
	state $rc = require Mojo::UserAgent;

	my %hash;
	$hash{cves}  = $cve // die "Need CVE argument\n";
	$hash{distribution}  = $distribution;
	$hash{distribution} =~ s/::/-/g;

	my $serial = $hash{cves} =~ s/\ACVE-//r;

	my $json = Mojo::UserAgent->new->get( "$base/$hash{cves}" )->result->json;
	my $item = $json->{result}{CVE_Items}[0];

	$hash{description}  = $item->{cve}{description}{description_data}[0]{value};
	$hash{description}  =~ s/\v/ /g;

	my @references = map { $_->{url} } $item->{cve}{references}{reference_data}->@*;
	$hash{references} = \@references;

	$hash{reported} = $item->{publishedDate} =~ s/T.*//r;
	$hash{cves} = [ $hash{cves} ];

	$hash{severity} = eval { lc $item->{impact}{baseMetricV3}{cvssV3}{baseSeverity} } || undef;

	my $package = guess_package( $item );
	$package =~ s/::/-/g;

	$hash{distribution} = $package unless defined $hash{distribution};
	$hash{id} = sprintf 'CPANSA-%s-%s', $hash{distribution}, $serial;

	$hash{affected_versions} = undef;
	$hash{fixed_versions} = undef;

        $hash{embedded_vulnerability} = { name => undef, distributed_version => undef };

	return \%hash
	}

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

# This hasn't turned out so useful
sub parse_cpe23uri ( $cpe23uri ) {
	state @keys = qw(
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
		);

	state $pattern = qr{  # colons not escaped
		(?<!
			\\
		)
		:
		}x;

	my %hash;
	@hash{@keys} = map { s|\\||gr } split /$pattern/, $cpe23uri;
	return \%hash;
	}

sub report_path ( $package ) {
	use File::Spec::Functions qw(catfile);
	catfile( 'cpansa', "CPANSA-$package.yml" );
	}

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

sub get_recorded_cves ( $base = 'cpansa' ) {
	state $rc = require YAML::XS;

	opendir( my $dh, $base ) or die "Could not open <$base>: $!";

	my %found;
	while( my $file = readdir($dh) ) {
		next unless $file =~ /\.yml\z/;
		my $path = catfile( $base, $file );
		my $yaml = eval { YAML::XS::LoadFile( $path ) };

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
			$yaml->@*;

		@found{@found_cves} = (1)x@found_cves;
		}

	return \%found;
	}

sub cve_ignored ( $cve ) {
	state $hash = get_ignored_cves();
	exists $hash->{$cve};
	}

sub cve_recorded ( $cve ) {
	state $hash = get_recorded_cves();
	exists $hash->{$cve};
	}

1;
