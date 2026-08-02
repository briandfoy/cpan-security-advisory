#!perl

use v5.10;
use File::Basename;

my $branch = 'update-reports-' . `date +%Y%m%d-%H%M`;
chomp $branch;

system "git",  "switch", "-c", $branch;

system "git add cpansa";

my @diffs = split /(?=^diff --git)/m, `git diff --staged`;

sub dumper { state $rc = require Data::Dumper; Data::Dumper->new([@_])->Indent(1)->Sortkeys(1)->Terse(1)->Useqq(1)->Dump }

foreach my $diff ( @diffs ) {
	my $path = ($diff =~ /diff --git (\S+)/ )[0] =~ s|a/||r;
	my( $file ) = basename( $path );
	my $dist = $file =~ s/.*CPANSA-(\S+).yml/$1/r;
	my( $cve ) = $diff =~ /^ \+ \h+ cves: \R\+ \h+ - \h+ (\S+) /xm;

	say "$cve - $dist - $file";

	my $message = "$cve for $dist";
	my @command = ( 'git', 'commit', '-m', $message, $path );
	system @command;
	}
