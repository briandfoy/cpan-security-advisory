package Local::Config::Base;
use v5.26;

use experimental qw(signatures);
use vars qw($AUTOLOAD);

use namespace::autoclean;
use Carp qw(carp croak);
use Local::CPANSA;
use Mojo::Util qw(dumper);

=encoding utf8

=head1 NAME

=head1 SYNOPSIS

=head1 DESCRIPTION

=over 4

=cut

sub AUTOLOAD ( $self, @args ) {
	my $method = $AUTOLOAD =~ s/.*:://r;
	croak( "Unknown method <$method>" ) unless $self->key_exists($method);

	   if( @args == 0 ) { $self->value_for( $method ) }
	elsif( @args == 1 ) { $self->set_value_for( $method, $args[0] ); $self }
	}

sub DESTROY { 1 }

=item * args_is_empty

=cut

sub args_is_empty ( $self ) { $self->{args}->@* == 0 }

=item * deep_cloned_args

=cut

sub deep_cloned_args ( $self ) { use Storable; Storable::dclone($self->{args}) }

=item * dump

=cut

sub dump ( $self ) {
	use Data::Dumper;
	Data::Dumper->new([$self->getopts_spec],[qw(opts)])->Indent(1)->Sortkeys(1)->Terse(1)->Useqq(1)->Dump
	}

=item * getopts_args

=cut

sub getopts_args ( $self ) {
	state $spec = $self->getopts_spec;
	$self->{spec} =  $spec;
	my %getopts_args =
		map  { $spec->{$_}{getopt} => \$spec->{$_}{value} }
		grep { exists $spec->{$_}{getopt} }
		keys $spec->%*;
	\%getopts_args;
	}

=item * getopts_spec

=cut

sub getopts_spec ( $self ) {
	croak "getopts_spec must be implemented in a subclass";
	}

=item * key_exists

=cut

sub key_exists ( $self, $key ) { exists $self->getopts_spec->{$key}	}

=item * new

=cut

sub new ( $class, @args ) {
	my $self = bless { args => [ @args ] }, $class;
	$self->process_args;
	$self->prompt(1) if $self->args_is_empty;
	$self->postprocess_args;

	$self;
	}

=item * postprocess_args

=cut

sub postprocess_args ( $self ) {
	croak "postprocess_args must be implemented in a subclass";
	}

=item * process_args

=cut

sub process_args ( $self ) {
	use Getopt::Long qw(:config no_ignore_case);
	my $args = $self->deep_cloned_args;
	$self->{getopts_args} = $self->getopts_args;
	my $ret = Getopt::Long::GetOptionsFromArray( $args, $self->{getopts_args}->%* );
	$self->leftover_args( $args );
	$self;
	}

=item * prompt_for_values

=cut

sub prompt_for_values ( $self ) {
	croak "prompt_for_values must be implemented in a subclass";
	}

=item * report_dir

=cut

sub report_dir ( $self ) { 'cpansa' }

=item * stdout_name

=cut

sub stdout_name ( $self ) { '-' }

=item * value_for

=cut

sub value_for ( $self, $key ) {
	unless( $self->key_exists( $key ) ) {
		carp "No option for <$key>";
		return;
		}

	$self->{spec}{$key}{value}
	}

=item * set_value_for

=cut

sub set_value_for ( $self, $key, $value ) {
	unless( $self->key_exists( $key ) ) {
		carp "No option for <$key>";
		return;
		}

	$self->getopts_spec->{$key}{value} = $value;
	$self;
	}

=back

=cut

__PACKAGE__;
