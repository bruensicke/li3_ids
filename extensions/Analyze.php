<?php

namespace li3_ids\extensions;

use lithium\core\Libraries;
use lithium\util\String;
use lithium\storage\Session;

/**
 * Analyze does the heavy Lifting
 *
 * It analyzes the Request paramters, like GET and POST
 * and runs it through the IDS Monitor.
 * It then can react on certain Impacts.
 */
class Analyze extends \lithium\core\Adaptable {

	/**
	 * Classes used by `Analyze`.
	 *
	 * @todo obsolete??
	 *
	 * @var array
	 */
	public static $_classes = array(
		'request' => 'lithium\action\Request',
		'logger' => 'lithium\analysis\Logger',
	);

	/**
	 * Placeholder for the Request Object
	 *
	 * @var array
	 */
	protected static $_requestInstance = NULL;

	/**
	 * Runs the PHPIDS Analyzer
	 *
	 * @param object $request The Request object
	 * @return boolean true on success, false otherwise
	 */
	public static function run($request){
		if(!$request) {
			return false;
		}

		self::$_requestInstance = $request;

		$data = array(
			'GET' => $request->query,
			'POST' => $request->data,
		);

		$path = get_include_path();
		set_include_path($path.':'.LI3_IDS_LIB_PATH);

		try {

			require_once  'IDS/Init.php';
			$init = \IDS_Init::init(LI3_IDS_LIB_PATH . '/IDS/Config/Config.ini.php');
			$init->config['General']['use_base_path'] = false;
			$init->config['General']['filter_path'] = LI3_IDS_LIB_PATH . '/IDS/default_filter.xml';
			$init->config['General']['tmp_path'] = Libraries::get(true, 'path') . '/resources/tmp/';
			$init->config['Logging']['path'] = Libraries::get(true, 'path') . '/resources/tmp/logs/phpids.log';
			$init->config['Caching']['path'] = Libraries::get(true, 'path') . '/resources/tmp/cache/default_filter.cache';

			$ids = new \IDS_Monitor($data, $init);
			$result = $ids->run();

			if($result instanceof \IDS_Report){
				static::react($result);
			}
		} catch (Exception $e){
			die($e->getMessage());
		}
		return true;
	}

	/**
	 * React
	 *
	 * @param object $result \IDS_Report
	 * @return	void
	 */
	protected static function react(\IDS_Report $result) {

		$current_impact = $result->getImpact();
		$config = self::config('default');

		$impact = Session::read('impact', array('name' => $config['session']));
		$impact += $current_impact;
		if(!Session::write('impact', (string)$impact, array('name' => $config['session']))){
			$msg = sprintf('Impact could not be written to Session "%s"', $config['session']);
			throw new \Exception($msg);
		}
		switch(true) {
			case $impact >= $config['threshold']['kick']:
				//IP to Blacklist
				static::log($result, 'kick', $impact);
				//die('Ihre IP wurde gesperrt!
				//Total impact:'.$impact.' vs '.$config['threshold']['kick']);
				break;
			case $impact >= $config['threshold']['warn']:
				//warn
				static::log($result, 'warn', $impact);
				break;
			case $impact >= $config['threshold']['mail']:
				//mail
				static::log($result, 'mail', $impact);
				break;
			case $impact >= $config['threshold']['log']:
				//log this
				static::log($result, 'log', $impact);
				break;
			default:
				//nothing
				break;
		}
	}

	/**
	 * Logs an IDS_Report
	 *
	 * @param object $result \IDS_Report
	 * @param string $threshold
	 * @param integer $totalImpact
	 * @return boolean
	 */
	protected static function log(\IDS_Report $result, $threshold, $total_impact) {
		$request = self::$_requestInstance;
		$params = compact('result', 'threshold', 'total_impact', 'request');

		$_classes = static::$_classes;

		return static::_filter(__FUNCTION__, $params, function($self, $params) use ($_classes) {
			$config = $self::config('default');
			$msg = String::insert($config['log_format'], array(
				'ip' => $params['request']->env('REMOTE_ADDR'),
				'total_impact' => $params['total_impact'],
				'impact' => $params['result']->getImpact(),
				'threshold' => $config['threshold'][$params['threshold']],
			));
			$_classes['logger']::write('warning', $msg, array('name' => $config['logger']));
		});
	}

	/**
	 * A stub method called by `_config()` which allows `Adaptable` subclasses to automatically
	 * assign or auto-generate additional configuration data, once a configuration is first
	 * accessed. This allows configuration data to be lazy-loaded from adapters or other data
	 * sources.
	 *
	 * @param string $name The name of the configuration which is being accessed. This is the key
	 *               name containing the specific set of configuration passed into `config()`.
	 * @param array $config Contains the configuration assigned to `$name`. If this configuration is
	 *              segregated by environment, then this will contain the configuration for the
	 *              current environment.
	 * @return array Returns the final array of settings for the given named configuration.
	 */
	protected static function _initConfig($name, $config) {
		$defaults = array(
			'adapter' => null,
			'session' => 'default', // name of Session config to use
			'logger' => 'ids', // name of Logger config to use
			'log_format' => '{:ip} - Total impact "{:total_impact}" is raised by "{:impact}" and higher than threshold "{:threshold}"',
			'threshold' => array(
				'log'  => 3,
				'mail' => 9,
				'warn' => 27,
				'kick' => 81,
			),
		);
		return (array) $config + $defaults;
	}
}

?>