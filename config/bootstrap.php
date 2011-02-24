<?php
/**
 *
 **/

use lithium\action\Dispatcher;
use li3_ids\extensions\Analyze;

//debug mode :)
\ini_set("display_errors", 1);


Dispatcher::applyFilter('run', function($self, $params, $chain) {
	Analyze::run($params);
	return $chain->next($self, $params, $chain);
});
 ?>