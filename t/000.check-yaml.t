use v5.10;
use strict;
use warnings;

use Test::More;

use Config qw(%Config);
use File::Spec::Functions qw(catfile);

my $YAMLLINT;

foreach my $dir ( split /$Config{path_sep}/, $ENV{PATH} ) {
	my $bin = catfile( $dir, 'yamllint' );
	next unless -x -e $bin;
	$YAMLLINT = $bin;
	diag( "yamllint is $YAMLLINT" );
	last;
	}

use YAML::XS qw(LoadFile);

my @files = glob('{.github/workflows,cpansa,external_reports}/*.yml');

subtest 'YAML::XS::LoadFile' => sub {
	foreach my $file ( @files ) {
		my $yaml = eval { LoadFile($file) };
		ok( defined $yaml, "$file is valid YAML" ) or diag( "$file: $@" );
		}
	};

subtest 'yamllint' => sub {
	SKIP: {
		skip 'No yamllint' unless defined $YAMLLINT;
		foreach my $file ( @files ) {
			my $output = `$YAMLLINT $file`;
			is( $?, 0, "yamllint clean for $file" ) or diag( "$file: $output" );
			}
		}
	};

done_testing();
