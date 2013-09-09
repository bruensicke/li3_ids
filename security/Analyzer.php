<?php

namespace li3_ids\security;

use lithium\core\Libraries;
use lithium\storage\Session;
use lithium\analysis\Logger;
use lithium\util\String;
use lithium\util\Set;

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
	public static function run($request, array $options = array()) {
		$defaults = self::config('default');
		$config = Set::merge($defaults, $options);
		self::$_request = $request;
		try {

			if (!empty($config['iniFile']) && file_exists($config['iniFile'])) {
				$init = Init::init($config['iniFile']);
				if (!empty($config['config'])) {
					$init->setConfig($config['config'], true);
				}
			} else {
				$init = new Init($config['config']);
			}

			$ids = new Monitor($init);
			$report = $ids->run(static::convertRequest($request, $config['request']));

			if (!$report->isEmpty()) {
				return static::react($report, $config);
			}

		} catch (Exception $e){
			die($e->getMessage());
		}
		return $report;
	}

	/**
	 * React on Report
	 *
	 * @param object $result \IDS_Report
	 * @return	void
	 */
	protected static function react(Report $report, array $config = array()) {
		if (empty($config)) {
			$config = static::config('default');
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
					$self::kick($report, $config['threshold']['kick'], $impact);
					break;
				case $impact >= $config['threshold']['warn']:
					$self::warn($report, $config['threshold']['warn'], $impact);
					break;
				case $impact >= $config['threshold']['mail']:
					$self::mail($report, $config['threshold']['mail'], $impact);
					break;
				case $impact >= $config['threshold']['log']:
					$self::log($report, $config['threshold']['log'], $impact);
					break;
				default:
					//nothing
					break;
			}
			return $report;
		});
	}

	/**
	 * Logs an Report
	 *
	 * @param object $result Instance of type `IDS\Report` as result of `IDS\Monitor::run()`
	 * @param integer $threshold
	 * @param integer $totalImpact
	 * @return boolean
	 */
	public static function log(Report $report, $threshold, $total_impact) {
		$params = compact('report', 'threshold', 'total_impact');
		return static::_filter(__FUNCTION__, $params, function($self, $params) {
			extract($params);
			$request = $self::getRequest();
			$config = $self::config('default');
			$name = $config['logger'];
			if ($name === false) {
				return true;
			}
			$msg = String::insert($config['log_format'], array(
				'ip' => $request->env('REMOTE_ADDR'),
				'total_impact' => $total_impact,
				'impact' => $report->getImpact(),
				'threshold' => $threshold,
			));
			return Logger::write($config['log_severity'], $msg, compact('name'));
		});
	}

	/**
	 * Mail an Report - by default this method just calls log
	 *
	 * You have to filter or overwrite this method in your adapter to implement custom logic.
	 *
	 * @see li3_ids\security\Analyzer::log()
	 * @param object $result Instance of type `IDS\Report` as result of `IDS\Monitor::run()`
	 * @param integer $threshold
	 * @param integer $totalImpact
	 * @return boolean
	 */
	public static function mail(Report $report, $threshold, $total_impact) {
		$params = compact('report', 'threshold', 'total_impact');
		return static::_filter(__FUNCTION__, $params, function($self, $params) {
			return $self::log($params['report'], $params['threshold'], $params['total_impact']);
		});
	}

	/**
	 * Warn user - by default this method just calls log
	 *
	 * You have to filter or overwrite this method in your adapter to implement custom logic.
	 *
	 * @see li3_ids\security\Analyzer::log()
	 * @param object $result Instance of type `IDS\Report` as result of `IDS\Monitor::run()`
	 * @param integer $threshold
	 * @param integer $totalImpact
	 * @return boolean
	 */
	public static function warn(Report $report, $threshold, $total_impact) {
		$params = compact('report', 'threshold', 'total_impact');
		return static::_filter(__FUNCTION__, $params, function($self, $params) {
			return $self::log($params['report'], $params['threshold'], $params['total_impact']);
		});
	}

	/**
	 * Kick user - by default this method just calls log
	 *
	 * You have to filter or overwrite this method in your adapter to implement custom logic.
	 *
	 * @see li3_ids\security\Analyzer::log()
	 * @param object $result Instance of type `IDS\Report` as result of `IDS\Monitor::run()`
	 * @param integer $threshold
	 * @param integer $totalImpact
	 * @return boolean
	 */
	public static function kick(Report $report, $threshold, $total_impact) {
		$params = compact('report', 'threshold', 'total_impact');
		return static::_filter(__FUNCTION__, $params, function($self, $params) {
			return $self::log($params['report'], $params['threshold'], $params['total_impact']);
		});
	}

	/**
	 * returns lithium request object that has been used in `Analyzer::run()`
	 *
	 * @see li3_ids\security\Analyzer::run()
	 * @see lithium\action\Request
	 * @return object $request The lithium Request object
	 */
	public static function getRequest() {
		return static::$_request;
	}

	/**
	 * converts a lithium request object into an array, that can be used for IDS inspection
	 *
	 * @see lithium\action\Request
	 * @param object $request The lithium Request object
	 * @return array an array containing all data to be inspected by PHP-IDS
	 */
	public static function convertRequest($request, array $options = array()) {
		$config = static::config('default');
		$options += $config['request'];
		$result = array();
		if ($options['get']) {
			$result['GET'] = $request->query;
		}
		if ($options['post']) {
			$result['POST'] = $request->data;
		}
		if ($options['cookie']) {
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
			'log_severity' => 'debug',
			'log_format' => '{:ip} - Total impact "{:total_impact}" is raised by "{:impact}" and higher than threshold "{:threshold}"',
			'threshold' => array(
				'log'  => 3,
				'mail' => 9,
				'warn' => 27,
				'kick' => 81,
			),
			'request' => array(
				'get' => true,
				'post' => true,
				'cookie' => true,
			),
			// 'iniFile' => LI3_IDS_PATH . '/config/bootstrap/ids.ini',
			'config' => array(
				'General' => array(
					'filter_type' => 'xml',
					'use_base_path' => false,
					'scan_keys' => false,
					'tmp_path' => $cachePath,
					'filter_path' => LI3_IDS_LIB_PATH . '/default_filter.xml',
					'html' => array(),
					'json' => array(),
					'exceptions' => array(),
				),
				'Caching' => array(
					'caching' => 'file', // session|file|database|memcached|none
					'expiration_time' => 600,
					'path' => $cachePath . '/ids_filter.cache',
				),
			),
		);
		return (array) Set::merge($defaults, $config);
	}
}

?>