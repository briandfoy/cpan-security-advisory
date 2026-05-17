use v5.42;
use utf8;

=encoding utf8

=head1 NAME

Local::CPANSA::ReviewQueue::Model::Items - handle the data interface for Items

=head1 SYNOPSIS

To run the demo:

	% morbo script/mojox-demo-htmx

=head1 DESCRIPTION

=over 4

=item * new(FILE)

Create a new model instance, reading from C<FILE> if it exists and is valid.
When the instance is destroyed, the current list of items will be written to
C<FILE>.

The default file is F<items.json>.

=item * add( label => $label, description => $description )

From the values for C<label> and C<description>, create a new
C<MojoX::Demo::Model::Item> instance and add it to the list of items.

=item * items

Return the array ref of items. Each element is an C<MojoX::Demo::Model::Item>
instance.

=item * save

Save the current list of items to the file.

=back


=head1 SOURCE AVAILABILITY

This module is on Github:

	https://github.com/briandfoy/

=head1 AUTHOR

brian d foy, C<< <briandfoy@pobox.com> >>

=head1 COPYRIGHT AND LICENSE

Copyright © 2026-2026, brian d foy C<< <briandfoy@pobox.com> >>. All rights reserved.
This software is available under the Artistic License 2.0.

=cut

package Local::CPANSA::ReviewQueue::Model::Item {
	use Mojo::Base -base;

	has $_ for qw(id date description);
	has active      => true;
	has handled     => false;
	has found       => false;

	sub id ($self) { $self->uuid }

	sub TO_JSON ($self) {
		my %hash = $self->%*;
		\%hash;
		}
	}

package Local::CPANSA::ReviewQueue::Model::Items;
use Mojo::File qw(curfile);
use Mojo::JSON qw(decode_json encode_json);

sub DESTROY ($self) { $self->save }

sub new ($class, $file = 'items.json') {
	my $items = do {
		if( -e $file ) {
			my $contents = Mojo::File->new($file)->slurp;
			$contents = [] unless length $contents;
			my $decoded = eval { decode_json($contents) } // [];
			my %h = map { my $item = MojoX::Demo::Model::Item->new($_); ($item->id => $item) } grep { ref } $decoded->@*;
			\%h;
			}
		else { {} }
		};

	my $self = bless { items => $items, file => $file }, $class;
	return $self;
	}

sub activate ($self, $id) {
	my $item = $self->get($id);
	$item->active(true);
	$self->save;
	$item;
	}

sub add ($self, %hash) {
	my $item = MojoX::Demo::Model::Item->new(
		label       => $hash{'label'},
		description => $hash{'description'},
		);

	$self->_items->{$item->id} = $item;
	$self->save;
	return $item;
	}

sub deactivate ($self, $id) {
	my $item = $self->get($id);
	$item->active(false);
	$self->save;
	$item;
	}

sub delete ($self, $id) {
	$self->get($id)->deleted(true);
	$self->save;
	}

sub get ($self, $id) {
	$self->{'items'}{$id} // MojoX::Demo::Model::Item->new;
	}

sub _items ($self) { $self->{'items'} }

sub items ($self) { [ values $self->_items->%* ] }

sub items_not_deleted ($self) {
	my @items = grep { ! $_->deleted } values $self->_items->%* ;
	\@items;
	}

sub save ($self) {
	Mojo::File->new( $self->{'file'} )->spurt( encode_json( $self->items_not_deleted ) );
	$self;
	}

sub update ($self, $id, $label, $description) {
	my $item = $self->get($id);
	$item->label($label);
	$item->description($description);
	$self->save;
	$item;
	}

__PACKAGE__;
