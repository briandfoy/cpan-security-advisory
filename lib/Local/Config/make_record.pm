use v5.26;

package Local::Config::make_record;
use parent qw(Local::Config::Base);

use experimental qw(signatures);

use namespace::autoclean;
use Carp qw(carp);
use Local::CPANSA;

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
		output_filename    => { order => 8, getopt => 'o=s',                   description => 'Output filename' },
		prompt             => { order => 0, getopt => "prompt|p",              description => undef },
		rt                 => { order => 3, getopt => "rt|r=i",                description => 'rt.cpan.org issue' },
		yes_yaml_start     => { order => 0, getopt => "s",                     description => undef },

		leftover_args           => { order => 0, value => [] },
		include_yaml_start_line	=> { order => 0, value => 1  },
		);

	\%opts
	}

sub guess_output_filename ( $self, $namespace = $self->value_for('namespace') ) {
	use File::Spec::Functions;
	Local::CPANSA::report_path( $namespace =~ s/::/-/gr )
	}

sub postprocess_args ( $self ) {
	my( $cve, $namespace ) = $self->leftover_args->@*;
	$self->cve( $cve ) if defined $cve;

	$self->output_filename( $self->stdout_name )
		if( ! $self->output_filename and $self->no_guess_filename );

	if( defined $namespace ) {
		$self->namespace($namespace);
		$self->output_filename( $self->guess_output_filename($namespace) )
			if( ! $self->no_guess_filename and ! $self->output_filename );
		}

	$self->prompt_for_values if $self->prompt;

	$self->include_yaml_start_line( 0 ) if $self->no_yaml_start;
	$self->include_yaml_start_line( 1 ) if $self->yes_yaml_start;

	$self;
	}

sub prompt_for_values ( $self ) {
	my $opts = $self->getopts_spec;
	my @prompt_keys =
		sort { $opts->{$a}{order} <=> $opts->{$b}{order} }
		grep { $opts->{$_}{order} }
		keys $opts->%*;

	foreach my $key ( @prompt_keys ) {
		printf $opts->{$key}{description} . ' [%s]> ', $self->$key();
		chomp( my $value = scalar <STDIN> );
		$value =~ s/\A\s+|\s+\z//g;
		next unless length $value;
		$self->$key($value);
		if( $key eq 'namespace' and  ! $self->output_filename ) {
			$self->output_filename( $self->guess_output_filename($value) )
			}
		}

	$self;
	}

__PACKAGE__;
