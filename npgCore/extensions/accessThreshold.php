<?php

/**
 * This plugin monitors front-end access and shuts down responses when a particular
 * source tries to flood the gallery with requests.
 *
 * A mask is used to control the scope of the data collection. For a IPv4 addresses
 * 	255.255.255.255 will resolve to the Host.
 *  255.255.255.0 will resolve to the Sub-net (data for all hosts in the Sub-net are grouped.)
 *  255.255.0.0 will resolve to the Network (data for the Network is grouped.)
 *
 * Access data is not acted upon until there is at least 10 access attempts. This insures
 * that flooding is not prematurely indicated.
 *
 * @author Stephen Billard (sbillard)
 * @Copyright 2016 by Stephen L Billard for use in {@link https://%GITHUB% netPhotoGraphics} and derivatives
 *
 * @package plugins/accessThreshold
 * @pluginCategory security
 */
$plugin_is_filter = 990 | FEATURE_PLUGIN;
$plugin_description = gettext("Tools to block denial of service attacks.");

$option_interface = 'accessThreshold';

class accessThreshold {

	function __construct() {
		if (OFFSET_PATH == 2) {
			setOption('accessThreshold_Owner', getUserIP()); //	if he ran setup he is the owner.
			setOptionDefault('accessThreshold_IP_RETENTION', 500);
			setOptionDefault('accessThreshold_THRESHOLD', 5);
			setOptionDefault('accessThreshold_IP_ACCESS_WINDOW', 3600);
			setOptionDefault('accessThreshold_SENSITIVITY', '255.255.255.0');
			setOptionDefault('accessThreshold_LocaleCount', 5);
			setOptionDefault('accessThreshold_LIMIT', 100);
			setOptionDefault('accessThreshold_Monitor', TRUE);
			//clear out the recentIP array
			setOption('accessThreshold_CLEAR', 1);
			self::handleOptionSave(NULL, NULL);
		}
	}

	function getOptionsSupported() {
		$options = array(
				gettext('Memory') => array('key' => 'accessThreshold_IP_RETENTION', 'type' => OPTION_TYPE_NUMBER,
						'order' => 5,
						'desc' => gettext('The number unique access attempts to keep.')),
				gettext('Threshold') => array('key' => 'accessThreshold_THRESHOLD', 'type' => OPTION_TYPE_NUMBER,
						'order' => 2,
						'desc' => gettext('Attempts will be blocked if the average access interval is less than this number of seconds.')),
				gettext('Window') => array('key' => 'accessThreshold_IP_ACCESS_WINDOW', 'type' => OPTION_TYPE_NUMBER,
						'order' => 1,
						'desc' => gettext('The access interval is reset if the last access is was more than this many seconds ago.')),
				gettext('Mask') => array('key' => 'accessThreshold_SENSITIVITY', 'type' => OPTION_TYPE_TEXTBOX,
						'order' => 4,
						'desc' => gettext('IP mask to determine the IP elements sensitivity')),
				gettext('Locale limit') => array('key' => 'accessThreshold_LocaleCount', 'type' => OPTION_TYPE_NUMBER,
						'order' => 3,
						'desc' => sprintf(gettext('Requests will be blocked if more than %d locales are requested.'), getOption('accessThreshold_LocaleCount'))),
				gettext('Limit') => array('key' => 'accessThreshold_LIMIT', 'type' => OPTION_TYPE_NUMBER,
						'order' => 6,
						'desc' => sprintf(gettext('The top %d accesses will be displayed.'), getOption('accessThreshold_LIMIT'))),
				gettext('Owner') => array('key' => 'accessThreshold_Owner', 'type' => OPTION_TYPE_TEXTBOX,
						'order' => 7,
						'desc' => sprintf(gettext('Requests from this IP will be ignored.') . ' <span class="logwarning">' . gettext('If your IP address is dynamically assigned you may need to update this on a regular basis.') . '</span>', getOption('accessThreshold_LIMIT'))),
				gettext('Mointor only') => array('key' => 'accessThreshold_Monitor', 'type' => OPTION_TYPE_CHECKBOX,
						'order' => 7,
						'desc' => sprintf(gettext('It this box is checked, data will be collected but visitors will not be blocked.'), getOption('accessThreshold_LIMIT'))),
				gettext('Clear list') => array('key' => 'accessThreshold_CLEAR', 'type' => OPTION_TYPE_CHECKBOX,
						'order' => 99,
						'desc' => gettext('Clear the access list.'))
		);
		return $options;
	}

	static function handleOptionSave($themename, $themealbum) {
		$x = str_replace(':', '.', getOption('accessThreshold_SENSITIVITY'));
		$sensitivity = 0;
		foreach (explode('.', $x) as $v) {
			if ($v) {
				$sensitivity++;
			} else {
				break;
			}
		}
		if (getOption('accessThreshold_CLEAR')) {
			$recentIP = array();
			setOption('accessThreshold_Owner', getUserIP());
		} else {
			if (file_exists(SERVERPATH . '/' . DATA_FOLDER . '/recentIP.cfg')) {
				$recentIP = getSerializedArray(file_get_contents(SERVERPATH . '/' . DATA_FOLDER . '/recentIP.cfg'));
			} else {
				$recentIP = array();
			}
		}
		purgeOption('accessThreshold_CLEAR');
		$recentIP['config'] = array(
				'accessThreshold_IP_RETENTION' => getOption('accessThreshold_IP_RETENTION'),
				'accessThreshold_THRESHOLD' => getOption('accessThreshold_THRESHOLD'),
				'accessThreshold_IP_ACCESS_WINDOW' => getOption('accessThreshold_IP_ACCESS_WINDOW'),
				'accessThreshold_LocaleCount' => getOption('accessThreshold_LocaleCount'),
				'accessThreshold_SENSITIVITY' => $sensitivity
		);
		file_put_contents(SERVERPATH . '/' . DATA_FOLDER . '/recentIP.cfg', serialize($recentIP));
	}

	static function admin_tabs($tabs) {
		global $_current_admin_obj;
		if ((npg_loggedin(ADMIN_RIGHTS) && $_current_admin_obj->getID())) {
			$subtabs = $tabs['admin']['subtabs'];
			$subtabs[gettext("access")] = PLUGIN_FOLDER . '/accessThreshold/admin_tab.php?page=admin&tab=access';
			$tabs['admin']['text'] = gettext("admin");
			$tabs['admin']['link'] = getAdminLink('admin-tabs/users.php') . '?page=admin&tab=users';
			$tabs['admin']['subtabs'] = $subtabs;
		}
		return $tabs;
	}

	static function walk(&$element, $key, $__time) {
		global $__previous, $__interval, $__count;
		if (isset($element['time'])) {
			$v = $element['time'];
		} else {
			$v = 0;
		}
		if ($__time - $v < 3600) { //only the within the last 10 minutes
			if ($__count > 0) {
				$__interval = $__interval + ($v - $__previous);
			}
			$__count++;
		} else {
			$element = NULL;
		}
		$__previous = $v;
	}

}

if (OFFSET_PATH) {
	npgFilters::register('admin_tabs', 'accessThreshold::admin_tabs', -100);
}
$me = getOption('accessThreshold_Owner');

if ($me && getUserIP() != $me) {
	$monitor = getOption('accessThreshold_Monitor');
	$mu = new npgMutex('aT');
	$mu->lock();
	if (file_exists(SERVERPATH . '/' . DATA_FOLDER . '/recentIP.cfg')) {
		$recentIP = getSerializedArray(file_get_contents(SERVERPATH . '/' . DATA_FOLDER . '/recentIP.cfg'));
	} else {
		$recentIP = array();
	}
	if (array_key_exists('config', $recentIP)) {
		$__time = time();
		$__config = $recentIP['config'];
		if (!isset($__config['accessThreshold_LocaleCount'])) {
			$__config['accessThreshold_LocaleCount'] = 5;
		}

		$full_ip = getUserIP();
		if (strpos($full_ip, '.') === false) {
			//ip v6
			$separator = ':';
		} else {
			$separator = '.';
		}
		$x = array_slice(explode($separator, $full_ip), 0, $__config['accessThreshold_SENSITIVITY']);
		$ip = implode($separator, $x);
		unset($x);

		if (isset($recentIP[$ip]['lastAccessed']) && $__time - $recentIP[$ip]['lastAccessed'] > $__config['accessThreshold_IP_ACCESS_WINDOW']) {
			$recentIP[$ip] = array(
					'accessed' => array(),
					'locales' => array(),
					'blocked' => 0,
					'interval' => 0
			);
		}
		$recentIP[$ip]['lastAccessed'] = $__time;
		if (!$monitor && isset($recentIP[$ip]['blocked']) && $recentIP[$ip]['blocked']) {
			file_put_contents(SERVERPATH . '/' . DATA_FOLDER . '/recentIP.cfg', serialize($recentIP));
			$mu->unlock();
			sleep(10);
			header("HTTP/1.0 503 Service Unavailable");
			header("Status: 503 Service Unavailable");
			header("Retry-After: 300");
			exit(); //	terminate the script with no output
		} else {
			$recentIP[$ip]['accessed'][] = array('time' => $__time, 'ip' => $full_ip);
			$__locale = i18n::getUserLocale();
			if (isset($recentIP[$ip]['locales'][$__locale])) {
				$recentIP[$ip]['locales'][$__locale]['ip'][$full_ip] = $__time;
			} else {
				$recentIP[$ip]['locales'][$__locale] = array('time' => $__time, 'ip' => array($full_ip => $__time));
			}

			$__previous = $__interval = $__count = 0;
			array_walk($recentIP[$ip]['locales'], 'accessThreshold::walk', $__time);
			foreach ($recentIP[$ip]['locales'] as $key => $data) {
				if (is_null($data)) {
					unset($recentIP[$ip]['locales'][$key]);
				}
			}
			if ($__count > $__config['accessThreshold_LocaleCount']) {
				$recentIP[$ip]['blocked'] = 1;
			}

			$__previous = $__interval = $__count = 0;
			array_walk($recentIP[$ip]['accessed'], 'accessThreshold::walk', $__time);
			foreach ($recentIP[$ip]['accessed'] as $key => $data) {
				if (is_null($data)) {
					unset($recentIP[$ip]['accessed'][$key]);
				}
			}
			if ($__count > 1) {
				$__interval = $__interval / $__count;
			} else {
				$__interval = 0;
			}
			$recentIP[$ip]['interval'] = $__interval;
			if ($__count > 10 && $__interval < $__config['accessThreshold_THRESHOLD']) {
				$recentIP[$ip]['blocked'] = 2;
			}
		}
		if (count($recentIP) - 1 > $__config['accessThreshold_IP_RETENTION']) {
			unset($recentIP['config']);
			$recentIP = sortMultiArray($recentIP, array('lastAccessed'), true, true, false, true);
			$recentIP = array_slice($recentIP, 0, $__config['accessThreshold_IP_RETENTION']);
			$recentIP['config'] = $__config;
		}
		file_put_contents(SERVERPATH . '/' . DATA_FOLDER . '/recentIP.cfg', serialize($recentIP));
		$mu->unlock();

		unset($ip);
		unset($full_ip);
		unset($recentIP);
		unset($__config);
		unset($__time);
		unset($__interval);
		unset($__previous);
		unset($__count);
		unset($__locale);
	}
}
?>