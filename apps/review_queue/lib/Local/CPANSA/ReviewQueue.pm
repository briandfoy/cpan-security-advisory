package Local::CPANSA::ReviewQueue;
use Mojo::Base 'Mojolicious', -signatures;

sub startup ($app) {
	$app->moniker('review_queue');

	my $config = $app->plugin('JSONConfig');
	$app->secrets($config->{secrets});

	my $r = $app->routes;
	$r->get('/')->to('SPA#main');
	}

1;
