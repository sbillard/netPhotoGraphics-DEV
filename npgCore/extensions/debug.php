<?php

/**
 * Debugging aids
 *
 * <b><i>Mark release</i> button:</b>
 *
 * This button is placed in the <i>Development</i> section of
 * admin utilities. It button inserts or removes the qualifiers from the version file
 * so that the install is switched between a <i>normal</i> install and a debugging one.
 * Options are provided that control which debugging options are enabled.
 *
 * <b>Debugging aid tabs:</b>
 *
 * Adds <i>Development</i> subtabs for:
 * <dl>
 * 	<dt><var>PHP info</var></dt><dd>displays the output from the PHP <var>php phpinfo()</var> function.</dd>
 * 	<dt><var>Locales</var></dt><dd>displays information about server supported <i>locales</i>.</dd>
 * 	<dt><var>Sessions</var></dt><dd>displays the content of the PHP <var>_SESSIONS()</var> variable.</dd>
 * 	<dt><var>HTTP Accept</var></dt><dd>displays language preferences of your browser.</dd>
 * 	<dt><var>Cookies</var></dt><dd>displays your browser <i>cookies</i>.</dd>
 * </dl>
 *
 * @author Stephen Billard (sbillard)
 *
 * Copyright 2014 by Stephen L Billard for use in {@link https://%GITHUB% netPhotoGraphics} and derivatives
 *
 * @package plugins/debug
 * @pluginCategory development
 */
$plugin_is_filter = 10 | ADMIN_PLUGIN;
$plugin_description = gettext("Debugging aids.");

$option_interface = 'debug';

npgFilters::register('admin_tabs', 'debug::tabs', 100);
npgFilters::register('admin_utilities_buttons', 'debug::button');

if (isset($_GET['markRelease'])) {
	XSRFdefender('markRelease');
	$version = debug::version($_GET['markRelease'] == 'released');
	setOption('markRelease_state', $version);
	debug::updateVersion($version);
	header('location:' . getAdminLink('admin.php') . '?marked=' . $_GET['markRelease']);
	exit();
} else {
	preg_match('/-(.*)/', NETPHOTOGRAPHICS_VERSION, $_version);
	if (isset($_version[1])) {
		$_version = $_version[1];
	} else {
		$_version = '';
	}
	preg_match('/-(.*)/', strval(getOption('markRelease_state')), $_option);
	if (isset($_option[1])) {
		$_option = $_option[1];
	} else {
		$_option = '';
	}
	if ($_version != $_option) {
		if ($_version) {
			//	update the debug_marks option so that it matches the version string
			$marks = explode('_', $_version);
			array_shift($marks);
			setOption('debug_marks', serialize($marks));
			unset($marks);
		}
		$_version = debug::version(false);
		setOption('markRelease_state', $_version);
		debug::updateVersion($_version);
	}

	unset($_option);
	unset($_version);
}

class debug {

	function __construct() {
		if (OFFSET_PATH == 2) {
			if (TEST_RELEASE) {
				//	then the options must match the version tags
				$options = explode('-', NETPHOTOGRAPHICS_VERSION . '-');
				$options = explode('_', $options[1]);
				array_shift($options);
				setOption('debug_marks', serialize($options));
			} else {
				$options = getOptionsLike('debug_mark_');
				if ($options) {
					foreach ($options as $option => $value) {
						if ($value) {
							$object = strtoupper(str_replace('debug_mark_', '', $option));
							$list[$object] = $object;
						}
						purgeOption($option);
					}
					$options = $list;
					$update = true;
				}
			}
			$update = false;
			if (empty($options)) {
				$options = getSerializedArray(getOption('debug_marks'));
			}
			$key = array_search('DISPLAY', $options);
			if ($key !== false) {
				$key2 = array_search('ERRORS', $options);
				if ($key2 == $key + 1) {
					unset($options[$key2]);
					$options[$key] = 'DISPLAY‑ERRORS';
					$update = true;
				}
			} else {
				$key = array_search('DISPLAY_ERRORS', $options);
				if ($key !== false) {
					$options[$key] = 'DISPLAY‑ERRORS';
					$update = true;
				}
			}
			if ($update) {
				setOption('debug_marks', serialize($options));
				self::handleOptionSave(NULL, NULL);
			}

			$version = debug::version(true);
			setOptionDefault('jQuery_Migrate_theme', 0);
			setOptionDefault('jQuery_Migrate_admin', 0);
			setOptionDefault('jQuery_v1', 0);
			setOptionDefault('markRelease_state', $version);
		}
	}

	function getOptionsSupported() {
		$options = array(
				1 => array('key' => '', 'type' => OPTION_TYPE_NOTE, 'desc' => '<p class="warningbox">' . gettext('Note: These options are enabled only when the release is marked in <em>debug</em> mode.') . '</p>'),
				gettext('jQuery migration (admin)') => array('key' => 'jQuery_Migrate_admin', 'type' => OPTION_TYPE_RADIO,
						'buttons' => array(// The definition of the radio buttons to choose from and their values.
								gettext('Disabled') => 0,
								gettext('Production') => 1,
								gettext('Debug') => 2
						),
						'order' => 2,
						'desc' => gettext('Adds the <a href="https://jquery.com/upgrade-guide/3.0/">jQuery 3.3 migration</a> tool to the administrative pages.')),
				gettext('jQuery migration (theme)') => array('key' => 'jQuery_Migrate_theme', 'type' => OPTION_TYPE_RADIO,
						'buttons' => array(// The definition of the radio buttons to choose from and their values.
								gettext('Disabled') => 0,
								gettext('Production') => 1,
								gettext('Debug') => 2,
								gettext('No migration') => 3
						),
						'order' => 3,
						'desc' => gettext('Adds the <a href="https://jquery.com/upgrade-guide/">jQuery migration</a> tool to theme pages. (If <em>No migration</em> is selected jQuery v1.12 and jQuery migration v1.4.1 will be loaded instead of jQuery v3.'))
		);
		if (npgFunctions::hasPrimaryScripts()) {
			$list = array(
					gettext('Display PHP errors') => 'DISPLAY‑ERRORS',
					gettext('<em>testing mode</em>') => 'TESTING',
					gettext('<em>disable auto protect scripts</em>') => 'UNPROTECT',
					gettext('<em>show plugin load times</em>') => 'PLUGINS',
					gettext('Log 403 forbidden image processing information') => '403',
					gettext('Log 404 error processing debug information') => '404',
					gettext('Log the <em>EXPLAIN</em> output from SQL SELECT queries') => 'EXPLAIN',
					gettext('Log filter application sequence') => 'FILTERS',
					gettext('Log image processing debug information') => 'IMAGE',
					gettext('Log language selection processing') => 'LOCALE',
					gettext('Log admin saves and login attempts') => 'LOGIN',
					gettext('Log Feed issues') => 'FEED',
					gettext('Log Managed Objects changes') => 'OBJECTS'
			);
			$options[NULL] = array('key' => 'debug_marks', 'type' => OPTION_TYPE_CHECKBOX_ARRAYLIST,
					'checkboxes' => $list,
					'order' => 1,
					'desc' => gettext('<em>Testing mode</em> adds unique ids to the urls of javaScript and CSS files to bypass the cache expires settings.') . '<br/>' .
					gettext('If <em>disable auto protect scripts</em> is checked <em>Setup</em> will not protect its scrpts after an install.') . '<br/>' .
					gettext('<em>show plugin load times</em> lists load times for individual plugins in the <code>Script processing</code> HTML comments at the end of the page.')
			);
		}
		return $options;
	}

	function handleOptionSave($themename, $themealbum) {
		$version = self::version(false);
		if (TEST_RELEASE && NETPHOTOGRAPHICS_VERSION != $version) {
			self::updateVersion($version);
			setOption('markRelease_state', $version);
		}
	}

	static function updateVersion($version) {
		$v = file_get_contents(CORE_SERVERPATH . 'version.php');
		$version = "define('NETPHOTOGRAPHICS_VERSION', '$version');\n";
		$v = preg_replace("~define\('NETPHOTOGRAPHICS_VERSION.*\n~", $version, $v);
		file_put_contents(CORE_SERVERPATH . 'version.php', $v);
	}

	static function version($released) {
		if ($released) {
			return NETPHOTOGRAPHICS_VERSION_CONCISE;
		} else {
			$options = '';
			$list = getSerializedArray(getOption('debug_marks'));
			sort($list);
			$options = rtrim('-DEBUG_' . implode('_', $list), '_');
			return NETPHOTOGRAPHICS_VERSION_CONCISE . $options;
		}
	}

	static function button($buttons) {
		$text = array('released' => gettext('released'), 'debug' => gettext('debug'));
		if (TEST_RELEASE) {
			$mark = BULLSEYE_GREEN;
			$action = 'released';
		} else {
			$mark = BULLSEYE_RED;
			$action = 'debug';
		}

		$buttons[] = array(
				'category' => gettext('Development'),
				'enable' => true,
				'button_text' => gettext('Mark release'),
				'formname' => 'markRelease_button',
				'action' => '?markRelease=' . $action,
				'icon' => $mark,
				'title' => sprintf(gettext('Edits the version.php file making a “%s” install.'), $text[$action]),
				'alt' => '',
				'rights' => ADMIN_RIGHTS,
				'XSRFTag' => 'markRelease'
		);
		return $buttons;
	}

	static function tabs($tabs) {
		if (npg_loggedin(DEBUG_RIGHTS)) {
			if (!isset($tabs['development'])) {
				$tabs['development'] = array('text' => gettext("development"),
						'link' => getAdminLink(PLUGIN_FOLDER . '/debug/admin_tab.php'),
						'default' => (npg_loggedin(ADMIN_RIGHTS)) ? 'phpinfo' : 'http',
						'rights' => DEBUG_RIGHTS);
			}
			if (npg_loggedin(ADMIN_RIGHTS)) {
				$tabs['development']['subtabs'][gettext("phpinfo")] = PLUGIN_FOLDER . '/debug/admin_tab.php?page=develpment&tab=phpinfo';
				$tabs['development']['subtabs'][gettext("Locales")] = PLUGIN_FOLDER . '/debug/admin_tab.php?page=develpment&tab=locale';
				$tabs['development']['subtabs'][gettext("Session")] = PLUGIN_FOLDER . '/debug/admin_tab.php?page=develpment&tab=session';
				$tabs['development']['subtabs'][gettext("SERVER")] = PLUGIN_FOLDER . '/debug/admin_tab.php?page=develpment&tab=server';
				$tabs['development']['subtabs'][gettext("ENV")] = PLUGIN_FOLDER . '/debug/admin_tab.php?page=develpment&tab=env';
			}
			$tabs['development']['subtabs'][gettext("HTTP accept")] = PLUGIN_FOLDER . '/debug/admin_tab.php?page=develpment&tab=http';
			$tabs['development']['subtabs'][gettext("Cookies")] = PLUGIN_FOLDER . '/debug/admin_tab.php?page=develpment&tab=cookie';
			$tabs['development']['subtabs'][gettext("filters")] = PLUGIN_FOLDER . '/debug/admin_tab.php?page=development&tab=filters';
		}
		return $tabs;
	}

}
