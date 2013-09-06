<?php

use li3_ids\security\Analyzer;

use lithium\core\Libraries;
use lithium\action\Dispatcher;

$cachePath = Libraries::get(true, 'resources') . '/tmp/cache';

/**
 * Configure how IDS should behave
 *
 * @see at li3_ids\security\Analyzer::_initConfig() for available configurations
 */
Analyzer::config(array(
	'default' => array(
		'iniFile' => LI3_IDS_PATH . '/config/bootstrap/ids.ini',
		'config' => array(
			'General' => array(
				'filter_path' => LI3_IDS_LIB_PATH . '/default_filter.xml',
				'tmp_path' => $cachePath,
			),
			'Caching' => array(
				'path' => $cachePath . '/ids_filter.cache',
			),
		),
		'threshold' => array(
			'log'  => 3,
			'mail' => 9,
			'warn' => 27,
			'kick' => 81,
		),
		'severity' => array(
			'log'  => 'info',
			'mail' => 'warning',
			'warn' => 'warning',
			'kick' => 'error',
		),
		// 'email' => array(
		// 	'admin@example.com',
		// ),
	),
));

/**
 * Apply filter to Dispatcher, so we can analyze the request
 */
Dispatcher::applyFilter('run', function($self, $params, $chain) {
	Analyzer::run($params['request']);
	return $chain->next($self, $params, $chain);
});


?>