use Test::More;

use YAML::XS qw(LoadFile);

my @files = glob('{.github/workflows,cpansa,external_reports}/*.yml');

foreach my $file ( @files ) {
	my $yaml = eval { LoadFile($file) };
	ok( defined $yaml, "$file is valid YAML" ) or diag( "$file: $@" );
	}

done_testing();
