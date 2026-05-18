use v5.22;
package Local::Attributes;
use experimental qw(signatures);

use Exporter qw(import);
our @EXPORT = qw(
	MODIFY_CODE_ATTRIBUTES
	ATTRIBUTE_EXPORT_OK
	ATTRIBUTE_EXPORT_TAG
	);

use B;

sub MODIFY_CODE_ATTRIBUTES ( $package, $code_ref, @attributes ) {
	my( $sub_name ) = B::svref_2object( $code_ref )->GV->NAME;

	my @bad_attributes = ();
	foreach my $attribute ( @attributes ) {
		my( $attribute_name ) = map { uc() } $attribute =~ m/\A(\w+)/;
		no strict 'refs';
		if( exists &{"ATTRIBUTE_$attribute_name"} ) {
			my $method = "ATTRIBUTE_$attribute_name";
			push @bad_attributes, $attribute if $package->$method( $code_ref, $attribute );
			}
		else { push @bad_attributes, $attribute }
		}

	@bad_attributes;
	}

sub ATTRIBUTE_EXPORT_OK ( $package, $code_ref, $attribute ) {
	my( $sub_name ) = B::svref_2object( $code_ref )->GV->NAME;

	no strict 'refs';
	push @{ join '::', $package, "EXPORT_OK" }, $sub_name;
	return;
	}

sub ATTRIBUTE_EXPORT_TAG ( $package, $code_ref, $attribute ) {
	my( $sub_name ) = B::svref_2object( $code_ref )->GV->NAME;
	my( $tags ) = $attribute =~ m/ \A Export_Tag \( \s* " ([^"]+) " \s* \) /ix;
	my @tags = $tags =~ m/(\S+)/g;
	no strict 'refs';
	push ${ join '::', $package, "EXPORT_TAGS" }{$_}->@*, $sub_name for @tags;
	return;
	}

1;
