use strict;
use warnings;

use Test::More;

use Config qw(%Config);
use File::Spec::Functions qw(catfile);
use YAML::XS qw(LoadFile);

my $YAMLLINT = find_yamllint();

my $last_run_semaphore = catfile( 'xt', '.last_run' );
END {
	open my $fh, '>', $last_run_semaphore;
	print { $fh } $$;
	close $fh;
	}

my @all_files = glob('{cpansa,external_reports,generated_reports}/*.yml');
my $files_to_test = \@all_files;

if( $ENV{TEST_CHANGED_ONLY} ) {
	my $last_run_time = (stat($last_run_semaphore))[9] // -1;
	if( $last_run_time > -1 ) {
		my $formatted = format_seconds( time - $last_run_time );
		diag( "Last run was $formatted ago" );
		}

	my @modified_since_last_run = grep { (stat)[9] > $last_run_time } @all_files;
	diag( sprintf "Found %d files, %d modified since last run", scalar @all_files, scalar @modified_since_last_run );

	note( <<"HERE" );
Only testing files modified since last run.
Delete $last_run_semaphore or set TEST_ALL_YAML=1 to test all files
HERE
	$files_to_test = \@modified_since_last_run;
	pass() unless @modified_since_last_run;
	}

diag( @$files_to_test . ' files to test' );
subtest 'YAML::XS::LoadFile' => sub {
	my $start = time;
	diag( "Checking with YAML::XS" );
	SKIP: {
		skip 'No new files' unless @$files_to_test;
		foreach my $file ( @$files_to_test ) {
			my $yaml = eval { LoadFile($file) };
			ok( defined $yaml, "$file is valid YAML" ) or diag( "$file: $@" );
			}
		}
	diag( "  Elapsed: " . (time-$start) . " seconds" );
	};

subtest 'yamllint' => sub {
	my $start = time;
	diag( "Checking with yamllint" );
	SKIP: {
		skip 'No yamllint' unless defined $YAMLLINT;
		skip 'No new files' unless @$files_to_test;
		foreach my $file ( @$files_to_test ) {
			my $output = `$YAMLLINT -c xt/yamllint.config $file`;
			is( $?, 0, "yamllint clean for $file" ) or diag( "$file: $output" );
			}
		}
	diag( "  Elapsed: " . (time-$start) . " seconds" );
	};

done_testing();

sub find_yamllint {
	my $found;
	foreach my $dir ( split /$Config{path_sep}/, $ENV{PATH} ) {
		my $bin = catfile( $dir, 'yamllint' );
		next unless -x -e $bin;
		$found = $bin;
		diag( "yamllint is $found" );
		last;
		}

	return $found;
	}

sub format_seconds {
	my( $seconds ) = @_;

	my @bins = (
		[ 315_360_000, 'decades' ], # 0 is 1970!
		[  31_536_000, 'years'   ],
		[      86_400, 'days'    ],
		[       3_600, 'hours'   ],
		[          60, 'minutes' ],
		[           1, 'seconds' ],
		);

	foreach my $bin ( @bins ) {
		next if $seconds < $bin->[0];
		return sprintf "%.1f %s", $seconds / $bin->[0], $bin->[1];
		}
	}
