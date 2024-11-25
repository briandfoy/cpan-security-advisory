package # hide from PAUSE
	Local::Rx;

use Data::Rx;

use Local::Rx::Type::CommitID;
use Local::Rx::Type::CVE;
use Local::Rx::Type::GHSA;
use Local::Rx::Type::URL;
use Local::Rx::Type::VCS_URL;
use Local::Rx::Type::YYYYMMDD;

sub new {
	Data::Rx->new({
		type_plugins => [qw(
			Local::Rx::Type::YYYYMMDD
			Local::Rx::Type::GHSA
			Local::Rx::Type::CVE
			Local::Rx::Type::URL
			Local::Rx::Type::VCS_URL
			Local::Rx::Type::CommitID
			)],
	});
	}

__PACKAGE__;
