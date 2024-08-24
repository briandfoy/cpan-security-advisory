package Local::CPANSA;
use v5.26;
use experimental qw(signatures);

=encoding utf8

=head1 NAME

Local::CPANSA - tools for working within the repo

=head1 SYNOPSIS

=head1 DESCRIPTION

=over 4

=cut

=item * assemble_record

=cut

sub assemble_record ( $cve, $distribution = undef ) {
	state $base = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=';
	state $rc = require Mojo::UserAgent;

	my %hash;
	$hash{cves}  = $cve // die "Need CVE argument\n";
	$hash{distribution}  = $distribution;
	$hash{distribution} =~ s/::/-/g;

	my $serial = $hash{cves} =~ s/\ACVE-//r;

	my $url = "$base$hash{cves}";

	my $json = Mojo::UserAgent->new->get( $url )->result->json;

	my $item = $json->{vulnerabilities}[0]{cve};

	$hash{description}  = (map { $_->{value} } grep { $_->{lang} eq 'en' } $item->{descriptions}->@* )[0] // '';
	$hash{description}  =~ s/\v/ /g;

	my @references = map { $_->{url} } $item->{references}->@*;
	$hash{references} = \@references;

	$hash{reported} = $item->{published} =~ s/T.*//r;
	$hash{cves} = [ $hash{cves} ];

	$hash{severity} = eval { lc $item->{metrics}{cvssMetricV31}{cvssData}{baseSeverity} } || undef;

	my $package = guess_package( $item );
	$package =~ s/::/-/g;

	$hash{distribution} = $package unless defined $hash{distribution};
	$hash{id} = sprintf 'CPANSA-%s-%s', $hash{distribution}, $serial;

	$hash{affected_versions} = undef;
	$hash{fixed_versions} = undef;

	$hash{embedded_vulnerability} = { name => undef, distributed_version => undef };

	return \%hash
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

=item * report_path

=cut

sub report_path ( $package ) {
	use File::Spec::Functions qw(catfile);
	catfile( 'cpansa', "CPANSA-$package.yml" );
	}

=item * get_all_reports

=cut

sub get_all_reports ( $base_dir = 'cpansa' ) {
	opendir( my $dh, $base_dir ) or die "Could not open <$base_dir>: $!";
	my @files = map { catfile $base_dir, $_ } grep ! /\A\./, readdir($dh);
	return \@files;
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
			$yaml->@*;

		@found{@found_cves} = (1)x@found_cves;
		}

	return \%found;
	}

=item * load_report

=cut

sub load_report ( $report_path ) {
	state $rc = require YAML::XS;
	my $yaml = eval { YAML::XS::LoadFile( $report_path ) };
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

=back

=cut

1;
