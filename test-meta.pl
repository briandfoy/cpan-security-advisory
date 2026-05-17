use v5.40;
use lib qw(/Users/brian/Dev/cpan-security-advisory/lib);
use MetaCPAN::Client;
use Local::CPANSA;
use Data::Dumper;
use Storable;
use Digest::SHA qw(sha256_hex);
use Mojo::File;

local @ARGV = 'Business::ISBN10';

my $hash = Local::CPANSA::get_dist_info($ARGV[0]);

say dumper($hash);

sub dumper { state $rc = require Data::Dumper; Data::Dumper->new([@_])->Indent(1)->Sortkeys(1)->Terse(1)->Useqq(1)->Dump }
