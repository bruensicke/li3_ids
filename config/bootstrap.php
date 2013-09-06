<?php

define('LI3_IDS_PATH', dirname(__DIR__));
define('LI3_IDS_LIB_PATH', LI3_IDS_PATH . '/libraries/phpids/lib/IDS');

/**
 * This file loads the external library PHPIDS
 *
 * Do not remove this line, or li3_ids is not able to function properly.
 */
require __DIR__ . '/bootstrap/libraries.php';

/**
 * This file defines the Analyzer configuration
 *
 * comment in this line, or duplicate to your own bootstrap.
 * Please make sure, you configure your Analyzer correctly.
 */
// require __DIR__ . '/bootstrap/analyzer.php';

/**
 * This file could be used to activate a session
 * but is not needed, if you already have one.
 *
 * Just make sure, you have a session name, that
 * you configure the Analyzer in bootstrap/ids.php
 */
// require __DIR__ . '/bootstrap/session.php';

?>