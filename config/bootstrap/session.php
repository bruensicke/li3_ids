<?php

/**
 * This configures your session storage. 
 */
use lithium\storage\Session;

Session::config(array(
	'ids' => array('adapter' => 'Php', 'session.name' => 'ids'),
));
