package Local::Config::Base;
use v5.26;

use experimental qw(signatures);
use vars qw($AUTOLOAD);

use namespace::autoclean;
use Carp qw(carp croak);
use Local::CPANSA;

sub AUTOLOAD ( $self, @args ) {
	my $method = $AUTOLOAD =~ s/.*:://r;
	croak( "Unknown method <$method>" ) unless $self->key_exists($method);

	   if( @args == 0 ) { $self->value_for( $method ) }
	elsif( @args == 1 ) { $self->set_value_for( $method, $args[0] ); $self }
	}

sub DESTROY { 1 }

sub args_is_empty ( $self ) { $self->{args}->@* == 0 }

sub deep_cloned_args ( $self ) { use Storable; Storable::dclone($self->{args}) }

sub dump ( $self ) {
	use Data::Dumper;
	Data::Dumper->new([$self->getopts_spec],[qw(opts)])->Indent(1)->Sortkeys(1)->Terse(1)->Useqq(1)->Dump
	}

sub getopts_args ( $self ) {
	state $opts = $self->getopts_spec;
	my %getopts_args =
		map  { $opts->{$_}{getopt} => \$opts->{$_}{value} }
		grep { exists $opts->{$_}{getopt} }
		keys $opts->%*;
	%getopts_args;
	}

sub getopts_spec ( $self ) {
	croak "getopts_spec must be implemented in a subclass";
	}

sub key_exists ( $self, $key ) { exists $self->getopts_spec->{$key}	}

sub new ( $class, @args ) {
	my $self = bless { args => [ @args ] }, $class;
	$self->process_args;
	$self->prompt(1) if $self->args_is_empty;
	$self->postprocess_args;

	$self;
	}

sub postprocess_args ( $self ) {
	croak "postprocess_args must be implemented in a subclass";
	}

sub process_args ( $self ) {
	use Getopt::Long qw(:config no_ignore_case);
	my $args = $self->deep_cloned_args;
	my $ret = Getopt::Long::GetOptionsFromArray( $args, $self->getopts_args );
	$self->leftover_args( $args );
	$self;
	}

sub prompt_for_values ( $self ) {
	croak "prompt_for_values must be implemented in a subclass";
	}

sub report_dir ( $self ) { 'cpansa' }

sub stdout_name ( $self ) { '-' }

sub value_for ( $self, $key ) {
	unless( $self->key_exists( $key ) ) {
		carp "No option for <$key>";
		return;
		}

	$self->getopts_spec->{$key}{value}
	}

sub set_value_for ( $self, $key, $value ) {
	unless( $self->key_exists( $key ) ) {
		carp "No option for <$key>";
		return;
		}

	$self->getopts_spec->{$key}{value} = $value;
	$self;
	}

__PACKAGE__;
