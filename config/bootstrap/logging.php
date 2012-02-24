<?php

/**
 * This configures your logging engine.
 */
use lithium\analysis\Logger;

Logger::config(array(
	'ids' => array(
		'adapter' => 'File',
		'priority' => array('emergency', 'alert', 'critical', 'error', 'warning')
	)
));
