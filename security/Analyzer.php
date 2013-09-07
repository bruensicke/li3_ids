<?php

namespace li3_ids\security;

use lithium\core\Libraries;
use lithium\storage\Session;
use lithium\analysis\Logger;
use lithium\util\String;

use IDS\Init;
use IDS\Report;
use IDS\Monitor;

use Exception;

/**
 * Analyzer does the heavy Lifting
 *
 * It analyzes the Request parameters, like GET and POST
 * and runs it through the IDS Monitor.
 * It then can react on certain Impacts.
 */
class Analyzer extends \lithium\core\Adaptable {

	/**
	 * Placeholder for the Request Object
	 *
	 * @var array
	 */
	protected static $_request = NULL;

	/**
	 * holds configuration per adapter
	 *
	 * @var array
	 */
	protected static $_configurations = array();

	/**
	 * Libraries::locate() compatible path to adapters for this class.
	 *
	 * @see lithium\core\Libraries::locate()
	 * @var string Dot-delimited path.
	 */
	protected static $_adapters = 'adapter.security.ids';

	/**
	 * Runs the PHPIDS Analyzer
	 *
	 * @see lithium\action\Request
	 * @param object $request The lithium Request object
	 * @return boolean true on success, false otherwise
	 */
	public static function run($request) {
		$config = self::config('default');
		self::$_request = $request;
		try {

			$init = Init::init($config['iniFile']);
			if (!empty($config['config'])) {
				$init->setConfig($config['config'], true);
			}

			$ids = new Monitor($init);
			$report = $ids->run(static::convertRequest($request));

			if (!$report->isEmpty()) {
				return static::react($report, $config);
			}

		} catch (Exception $e){
			die($e->getMessage());
		}
		return true;
	}

	/**
	 * React on Report
	 *
	 * @param object $result \IDS_Report
	 * @return	void
	 */
	protected static function react(Report $report, array $config = array()) {
		if (empty($config)) {
			$config = self::config('default');
		}
		$params = compact('report', 'config');
		return static::_filter(__FUNCTION__, $params, function($self, $params) {
			extract($params);
			$current_impact = $report->getImpact();

			if ($config['session'] !== false) {
				$name = $config['session'];
				$impact = Session::read('impact', compact('name'));
				$impact += $current_impact;
				Session::write('impact', (string) $impact, compact('name'));
			} else {
				$impact = $current_impact;
			}
			switch (true) {
				case $impact >= $config['threshold']['kick']:
					$self::log($report, 'kick', $impact);
					//die('Ihre IP wurde gesperrt!');
					break;
				case $impact >= $config['threshold']['warn']:
					//warn
					$self::log($report, 'warn', $impact);
					break;
				case $impact >= $config['threshold']['mail']:
					//mail
					$self::log($report, 'mail', $impact);
					break;
				case $impact >= $config['threshold']['log']:
					//log this
					$self::log($report, 'log', $impact);
					break;
				default:
					//nothing
					break;
			}
			return $impact;
		});
	}

	/**
	 * Logs an Report
	 *
	 * @param object $result IDS\Report
	 * @param string $threshold
	 * @param integer $totalImpact
	 * @return boolean
	 */
	public static function log(Report $report, $threshold, $total_impact) {
		$request = self::$_request;
		$params = compact('report', 'threshold', 'total_impact', 'request');
		return static::_filter(__FUNCTION__, $params, function($self, $params) {
			extract($params);
			$config = $self::config('default');
			$name = $config['logger'];
			if ($name === false) {
				return true;
			}
			$msg = String::insert($config['log_format'], array(
				'ip' => $request->env('REMOTE_ADDR'),
				'total_impact' => $total_impact,
				'impact' => $report->getImpact(),
				'threshold' => $config['threshold'][$threshold],
			));
			return Logger::write($config['severity'][$threshold], $msg, compact('name'));
		});
	}

	/**
	 * converts a lithium request object into an array, that can be used for IDS inspection
	 *
	 * @see lithium\action\Request
	 * @param object $request The lithium Request object
	 * @return array an array containing all data to be inspected by PHP-IDS
	 */
	public static function convertRequest($request, array $options = array()) {
		$defaults = array('GET' => true, 'POST' => true, 'COOKIE' => true);
		$options += $defaults;
		$result = array();
		if ($options['GET']) {
			$result['GET'] = $request->query;
		}
		if ($options['POST']) {
			$result['POST'] = $request->data;
		}
		if ($options['COOKIE']) {
			$result['COOKIE'] = $_COOKIE;
		}
		return $result;
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
		$cachePath = Libraries::get(true, 'resources') . '/tmp/cache';
		$defaults = array(
			'adapter' => null,
			'filters' => array(),
			'session' => 'li3_ids', // name of session config to use
			'logger' => 'default', // name of logger config to use
			'log_format' => '{:ip} - Total impact "{:total_impact}" is raised by "{:impact}" and higher than threshold "{:threshold}"',
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
		);
		return (array) $config + $defaults;
	}
}

?>