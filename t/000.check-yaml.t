use Test::More;

use YAML::XS qw(LoadFile);

my @files = glob('cpansa/*.yml');

foreach my $file ( @files ) {
	my $yaml = eval { LoadFile($file) };
	ok( defined $yaml, "$file is valid YAML" ) or diag( "$file: $@" );
	}

done_testing();
