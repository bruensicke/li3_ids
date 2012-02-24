<?php

use li3_ids\extensions\Analyze;

use lithium\analysis\Logger;
use lithium\action\Dispatcher;

define('LI3_IDS_PATH', dirname(dirname(__DIR__)));
define('LI3_IDS_LIB_PATH', LI3_IDS_PATH . '/libraries/phpids/lib');


/**
 * Configure how IDS should behave
 */
Analyze::config(array(
	'default' => array(
		'threshold' => array(
			'log'  => 3,
			'mail' => 9,
			'warn' => 27,
			'kick' => 81,
		),
		'email' => array(
			'admin@example.com',
		),
	),
));

/**
 * Apply filter to Dispatcher, so we can analyze the request
 */
Dispatcher::applyFilter('run', function($self, $params, $chain) {
	// debug($params);exit;
	Analyze::run($params['request']);
	return $chain->next($self, $params, $chain);
});


?>