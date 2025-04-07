use v5.26;

package Local::Config::make_record;
use parent qw(Local::Config::Base);

use experimental qw(signatures);

use namespace::autoclean;
use Carp qw(carp);
use Local::CPANSA;

=encoding utf8

=head1 NAME

Local::Config::make_record - stuff to create an advisory file

=head1 SYNOPSIS

=head1 DESCRIPTION

=over 4

=item * getopts_spec

=cut

sub getopts_spec ( $self ) {
	state %opts = (
		affected           => { order => 4, getopt => "affected|a=s",          description => 'Affected versions' },
		cve                => { order => 1, getopt => 'cve=s',                 description => 'CVE value' },
		fixed              => { order => 5, getopt => "fixed|f=s",             description => 'Fixed versions' },
		embedded_name      => { order => 6, getopt => "embedded_name|en=s",    description => 'Embedded library name' },
		embedded_version   => { order => 7, getopt => "embedded_version|ev=s", description => 'Embedded library version' },
		no_guess_filename  => { order => 0, getopt => "F",                     description => undef },
		no_yaml_start      => { order => 0, getopt => "S",                     description => undef },
		namespace          => { order => 2, getopt => 'namespace|n=s',         description => 'Perl namespace' },
		output_filename    => { order => 8, getopt => 'output_file|o=s',       description => 'Output filename' },
		prompt             => { order => 0, getopt => "prompt|p",              description => undef },
		rt                 => { order => 3, getopt => "rt|r=i",                description => 'rt.cpan.org issue' },
		yes_yaml_start     => { order => 0, getopt => "s",                     description => undef },

		leftover_args           => { order => 0, value => [] },
		include_yaml_start_line	=> { order => 0, value => 1  },
		);

	\%opts
	}

=item * guess_output_filename

=cut

sub guess_output_filename ( $self, $namespace = $self->value_for('namespace') ) {
	use File::Spec::Functions;
	Local::CPANSA::report_path( $namespace =~ s/::/-/gr )
	}

=item * new_meta( CONFIG )

=cut

sub new_meta ( $self, $config ) {
	state $rc = require MetaCPAN::Client;

	my %hash;

	my $mcpan = MetaCPAN::Client->new;
	my $package = $mcpan->package($config->namespace);
	my $dist = $mcpan->distribution($package->distribution);

	$hash{cpansa_version} = 2;
	$hash{darkpan} = 'false';
	$hash{distribution} = $package->distribution;
	$hash{last_checked} = time;
	$hash{latest_version} = $package->version;
	$hash{metacpan} = "https://metacpan.org/pod/" . $config->namespace;
	$hash{advisories} = [];

	$hash{repo} = $dist->github->{source} if keys  $dist->github->%*;

	\%hash;
	}

=item * postprocess_args

=cut

sub postprocess_args ( $self ) {
	my ($cve_arg, $package_arg ) = $self->leftover_args->@*;
	say "Leftover: CVE: $cve_arg PACKAGE: " . $package_arg // '<undef>';

	$self->cve( $cve_arg ) if defined $cve_arg;
	$self->namespace( $package_arg ) if defined $package_arg;

	$self->output_filename( $self->stdout_name )
		if( ! $self->output_filename and $self->no_guess_filename );

	my $namespace = $self->namespace;
	if( defined $namespace ) {
		$self->output_filename( $self->guess_output_filename($namespace) )
			if( ! $self->no_guess_filename and ! $self->output_filename );
		}

	$self->prompt_for_values if $self->prompt;

	$self->include_yaml_start_line( 0 ) if $self->no_yaml_start;
	$self->include_yaml_start_line( 1 ) if $self->yes_yaml_start;

	$self;
	}

=item * prompt_for_values

=cut

sub prompt_for_values ( $self ) {
	my $opts = $self->getopts_spec;
	my @prompt_keys =
		sort { $opts->{$a}{order} <=> $opts->{$b}{order} }
		grep { eval{ $opts->{$_}{order} } }
		keys $opts->%*;

	foreach my $key ( @prompt_keys ) {
		printf $opts->{$key}{description} . ' [%s]> ', $self->$key();

		chomp( my $value = scalar <STDIN> );
		$value =~ s/\A\s+|\s+\z//g;
		$self->$key($value) if length $value;

		if( $key eq 'namespace' and  ! $self->output_filename ) {
			$self->output_filename( $self->guess_output_filename($value) )
			}
		elsif( $key eq 'cve' ) {
			my $desc = Local::CPANSA::get_cve_description( $self->cve );
			say "=== CVE ===\n" . $desc . "\n===========\n";
			}
		}

	$self;
	}

=back

=cut

__PACKAGE__;
