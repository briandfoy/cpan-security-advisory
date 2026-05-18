use v5.42;
use utf8;
use lib qw(llib);

use Mojo::File;

use Test::More;

my $class = 'Local::CPANSA';
my @function_names = qw(
	find_root
	get_file_path
	);

my $known_root;

subtest 'known root' => sub {
    #                               ~~  root   /   t   / utils
	$known_root = Mojo::File->curfile->dirname->dirname->dirname;
	diag "known root is <$known_root>";
	ok -e $known_root->child('Makefile.PL'), 'Default target file is in root';
	ok -e $known_root->child('cpansa'), 'cpansa file is in root';
	};

subtest 'load' => sub {
	use_ok $class;
	can_ok $class, @function_names;

	$class->import( @function_names );
	ok do { no strict 'refs'; defined &{"$_"} }, "imported $_" for @function_names;
	};

subtest 'find_root' => sub {
	my $method = 'find_root';
	can_ok __PACKAGE__, $method;

	subtest 'no root' => sub {
		my $target = join "--", $$, time;
		my $root = find_root(__FILE__, $target);
		ok ! -e $known_root->child($target), 'bad target file does not exist';
		ok ! defined $root, 'root for bad file is undefined';
		};

	subtest 'root from argument' => sub {
		my $root = find_root(__FILE__);

		ok defined $root, 'root for this file is defined';
		is $root, $known_root, 'root matches known root';
		};

	subtest 'root from default' => sub {
		my $root = find_root();

		ok defined $root, 'root for default is defined';
		is $root, $known_root, 'root matches known root';
		};
	};

subtest 'get_file_path' => sub {
	my $method = 'get_file_path';
	can_ok __PACKAGE__, $method;

	subtest 'no such file' => sub {
		my $target = join "--", $$, time;
		my $paths = get_file_path("$target$target");
		isa_ok $paths, ref [];
		is scalar $paths->@*, 0, 'no files found'
		};

	subtest 'good file' => sub {
		my $paths = get_file_path('IGNORE_CVEs');
		isa_ok $paths, ref [];
		is scalar $paths->@*, 1, 'one file found: ' . $paths->[0];
		};
	};

done_testing;
