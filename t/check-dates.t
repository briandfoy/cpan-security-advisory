use v5.26;
use strict;
use warnings;
use experimental qw(signatures);

use Test::More;

use Config qw(%Config);
use File::Spec::Functions qw(catfile);
use YAML::XS qw(LoadFile);

my @all_files = glob('{cpansa,external_reports}/*.yml');

foreach my $file ( @all_files ) {
	subtest $file => sub {
		ok -e $file, "File $file exixts";
		my $yaml = eval { LoadFile($file) };
		ok( defined $yaml, "$file is valid YAML" ) or diag( "$file: $@" );
		test_dates($yaml);
		};
	}

sub test_dates ($yaml) {
	my $advisories = do {
		if( ref $yaml eq ref [] ) { $yaml } # cpansa
		elsif( ref $yaml eq ref {} ) { # external reports
			$yaml->{advisories}
			}
		};

	foreach my $advisory ( $advisories->@* ) {
		next unless exists $advisory->{reported};
		next unless defined $advisory->{reported};

		like $advisory->{reported}, qr/\A(19|20)\d\d-\d\d-\d\d\z/, 'Date has YYYY-MM-DD format';
		}
	}

done_testing();
