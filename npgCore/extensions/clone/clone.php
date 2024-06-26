<?php

/**
 *
 * site cloner
 *
 * @package admin/clone
 */
// UTF-8 Ø
define('OFFSET_PATH', 4);
require_once(dirname(dirname(__DIR__)) . '/admin-globals.php');
require_once(CORE_SERVERPATH . 'reconfigure.php');
require_once(CORE_SERVERPATH . 'lib-config.php');

admin_securityChecks(ADMIN_RIGHTS, currentRelativeURL());
XSRFdefender('clone');

if (isset($_GET['purge'])) {
	$clones = npgClone::clones(false);
	foreach ($clones as $clone => $data) {
		if (!$data['valid']) {
			query('DELETE FROM ' . prefix('plugin_storage') . ' WHERE `type`="clone" AND `aux`=' . db_quote($clone));
		}
	}
} else {
	$msg = array();
	$folder = sanitize($_GET['clonePath']);
	$newinstall = trim(sanitize($_GET['cloneWebPath']), '/') . '/';
	if (trim($folder, '/') == SERVERPATH) {
		$msg[] = gettext('You attempted to clone to the master install.');
		$succeed = false;
	} else {
		$succeed = true;
		$targets = array('docs' => 'dir', CORE_FOLDER => 'dir');

		//	handle the user plugin folder
		$pluginFiles = safe_glob(SERVERPATH . '/' . USER_PLUGIN_FOLDER . '/*', GLOB_ONLYDIR);
		foreach ($pluginFiles as $file) {
			if (!(file_exists($file . '.php') || is_link($file . '.php'))) {
				$targets[USER_PLUGIN_FOLDER . '/' . basename($file)] = 'copy';
			}
		}

		$pluginFiles = safe_glob(SERVERPATH . '/' . USER_PLUGIN_FOLDER . '/*.php');
		foreach ($pluginFiles as $file) {
			$pluginDir = USER_PLUGIN_FOLDER . '/' . stripSuffix(basename($file));
			if (is_dir(SERVERPATH . '/' . $pluginDir)) {
				$targets[$pluginDir] = 'dir';
			}
			$targets[USER_PLUGIN_FOLDER . '/' . basename($file)] = 'file';
		}

		foreach ($_gallery->getThemes() as $theme => $data) {
			$targets[THEMEFOLDER . '/' . $theme] = 'dir';
		}
		ksort($targets);

		if (!is_dir($folder . DATA_FOLDER)) {
			if (file_exists($folder . 'zp-data')) {
				chmod($folder . 'zp-data', 0777);
				if (!rename($folder . 'zp-data', $folder . DATA_FOLDER)) {
					$msg[] = gettext('The <code>zp-data</code> could not be renamed to <code>' . CONFIGFILE . '</code>.') . "<br />\n";
					$succeed = false;
				}
			} else {
				mkdir($folder . DATA_FOLDER);
			}
			chmod(SERVERPATH . '/' . DATA_FOLDER, FOLDER_MOD);
		}

		if (!file_exists($folder . '/' . DATA_FOLDER . '/' . CONFIGFILE)) {
			$path = str_replace(array(' ', '/'), '_', trim(str_replace(str_replace(WEBPATH, '/', SERVERPATH), '', $folder), '/')) . '_';
			$_config_contents = file_get_contents(SERVERPATH . '/' . DATA_FOLDER . '/' . CONFIGFILE);
			$_config_contents = configFile::update('mysql_prefix', $path, $_config_contents);
			file_put_contents($folder . '/' . DATA_FOLDER . '/' . CONFIGFILE, $_config_contents);
		}

		foreach (array(internalToFilesystem('charset_tést.cfg'), internalToFilesystem('charset.tést')) as $charset) {
			if (file_exists(SERVERPATH . '/' . DATA_FOLDER . '/' . $charset)) {
				if (file_exists($folder . DATA_FOLDER . '/' . $charset)) {
					chmod($folder . DATA_FOLDER . '/' . $charset, 0777);
					unlink($folder . DATA_FOLDER . '/' . $charset);
				}
				copy(SERVERPATH . '/' . DATA_FOLDER . '/' . $charset, $folder . DATA_FOLDER . '/' . $charset);
			}
		}

		if (file_exists($folder . USER_PLUGIN_FOLDER)) {
			if (is_link($folder . USER_PLUGIN_FOLDER)) {
				//	it is a symlink from older version of clone
				$succeed = npgClone::rmlink($folder . USER_PLUGIN_FOLDER);
			} else {
				//	discard plugins that no longer exist
				$pluginFiles = safe_glob($folder . USER_PLUGIN_FOLDER . '/*.php');
				foreach ($pluginFiles as $file) {
					$pluginDir = USER_PLUGIN_FOLDER . '/' . stripSuffix(basename($file));
					if (is_link($folder . $pluginDir) && !isset($targets[$pluginDir])) {
						$targets[$pluginDir] = 'discard';
					}
					if (is_link($folder . $pluginDir . '.php') && !isset($targets[$pluginDir . '.php'])) {
						$targets[$pluginDir . '.php'] = 'discard';
					}
				}
			}
		}

		if (file_exists($folder . THEMEFOLDER)) {
			//	discard themes that no longer exist
			$themeFiles = safe_glob($folder . THEMEFOLDER . '/*', GLOB_ONLYDIR);
			foreach ($themeFiles as $file) {
				$themeDir = THEMEFOLDER . '/' . basename($file);
				if (is_link($folder . $themeDir) && !isset($targets[$themeDir])) {
					$targets[$themeDir] = 'discard';
				}
			}
		}

		if (!is_dir($folder . USER_PLUGIN_FOLDER)) {
			mkdir($folder . USER_PLUGIN_FOLDER);
		}

		if (!is_dir($folder . THEMEFOLDER)) {
			mkdir($folder . THEMEFOLDER);
		}

		$success = true;
		foreach ($targets as $target => $type) {
			$link = is_link($folder . $target);
			$exists = $link || file_exists($folder . $target);
			$target8 = filesystemToInternal($target);

			switch ($type) {
				case 'dir':
					if ($exists) {
						if ($link) {
							$success = npgClone::rmlink($folder . $target);
						} else {
							$success = npgFunctions::removeDir($folder . $target);
						}
					} else {
						$success = true;
					}
					if ($success) {
						if ($success = SYMLINK && @symlink(SERVERPATH . '/' . $target, $folder . $target)) {
							if ($exists) {
								if ($link) {
									$msg[] = sprintf(gettext('The existing symlink <code>%s</code> was replaced.'), $target8) . "<br />\n";
								} else {
									$msg[] = sprintf(gettext('The existing folder <code>%s</code> was replaced.'), $target8) . "<br />\n";
								}
							} else {
								$msg[] = sprintf(gettext('Folder <code>%s</code> Link created.'), $target8) . "<br />\n";
							}
						} else {
							if ($exists) {
								if ($link) {
									$msg[] = sprintf(gettext('The existing symlink <code>%s</code> was removed but Link creation failed.'), $target8) . "<br />\n";
								} else {
									$msg[] = sprintf(gettext('The existing folder <code>%s</code> was removed but Link creation failed.'), $target8) . "<br />\n";
								}
							} else {
								$msg[] = sprintf(gettext('<code>%s</code> Link creation failed.'), $target8) . "<br />\n";
							}
						}
					} else {
						if ($link) {
							sprintf(gettext('The existing symlink <code>%s</code> could not be removed.'), $target8) . "<br />\n";
						} else {
							$msg[] = sprintf(gettext('The existing folder <code>%1$s</code> could not be removed.'), $target) . "<br />\n";
						}
					}

					break;

				case 'file':
					if ($exists) {
						$e = error_reporting(0);
						chmod($folder . $target, 0777);
						error_reporting($e);
						if (!npgClone::rmlink($folder . $target)) {
							if ($link) {
								$msg[] = sprintf(gettext('The existing symlink <code>%s</code> could not be removed.'), $target8) . "<br />\n";
							} else {
								$msg[] = sprintf(gettext('The existing file <code>%s</code> could not be removed.'), $target8) . "<br />\n";
							}
							$success = false;
							break;
						}
					}

					if ($success = SYMLINK && @symlink(SERVERPATH . '/' . $target, $folder . $target)) {
						if ($exists) {
							if ($link) {
								$msg[] = sprintf(gettext('The existing symlink <code>%s</code> was replaced.'), $target8) . "<br />\n";
							} else {
								$msg[] = sprintf(gettext('The existing file <code>%s</code> was replaced.'), $target8) . "<br />\n";
							}
						} else {
							$msg[] = sprintf(gettext('<code>%s</code> Link created.'), $target8) . "<br />\n";
						}
					} else {
						if ($exists) {
							$msg[] = sprintf(gettext('The existing file <code>%s</code> was removed but Link creation failed.'), $target8) . "<br />\n";
						} else {
							$msg[] = sprintf(gettext('<code>%s</code> Link creation failed.'), $target8) . "<br />\n";
						}
					}

					break;

				case 'copy':
					if ($exists) {
						if ($link) {
							$success = npgClone::rmlink($folder . $target);
						} else {
							if (is_dir($folder . $target)) {
								$success = npgFunctions::removeDir($folder . $target);
							} else {
								$success = @unlink($folder . $target);
							}
						}
					} else {
						$success = true;
					}

					if ($success && npgClone::copyDir(SERVERPATH . '/' . $target, $folder . $target)) {
						$msg[] = sprintf(gettext('Folder <code>%s</code> copied.'), $target8) . "<br />\n";
					} else {
						$msg[] = sprintf(gettext('Folder <code>%s</code> copy failed.'), $target8) . "<br />\n";
					}

					break;

				case 'discard':
					if (npgClone::rmlink($folder . $target)) {
						$msg[] = sprintf(gettext('Obsolete symlink <code>%s</code> discarded.'), $target8) . "<br />\n";
					} else {
						$msg[] = sprintf(gettext('Obsolete symlink <code>%s</code> could not be removed.'), $target8) . "<br />\n";
					}

					break;
			}

			$succeed = $succeed && $success;
		}
	}
	if ($succeed) {
		array_unshift($msg, '<h2>' . sprintf(gettext('Successful clone to %s'), $folder) . '</h2>' . "\n");
		list($diff, $needs) = checkSignature(4);
		if (empty($needs)) {
			$rslt = query_single_row('SELECT `id` FROM ' . prefix('plugin_storage') . ' WHERE `type`="clone" AND `aux`=' . db_quote(rtrim($folder, '/')));
			if (empty($rslt)) {
				query('INSERT INTO ' . prefix('plugin_storage') . '(`type`,`aux`,`data`) VALUES("clone",' . db_quote(rtrim($folder, '/')) . ',' . db_quote(trim($newinstall, '/')) . ')');
			} else {
				query('UPDATE ' . prefix('plugin_storage') . 'SET `data`=' . db_quote(trim($newinstall, '/')) . ' WHERE `id`=' . $rslt['id']);
			}
			$cloneid = bin2hex(rtrim($newinstall, '/'));
			$_SESSION['clone'][$cloneid] = array(
					'link' => $newinstall,
					'UTF8_image_URI' => UTF8_IMAGE_URI,
					'mod_rewrite' => MOD_REWRITE,
					'hash' => HASH_SEED,
					'strong_hash' => getOption('strong_hash'),
					'deprecated_functions_signature' => getOption('deprecated_functions_signature'),
					'zenphotoCompatibilityPack_signature' => getOption('zenphotoCompatibilityPack_signature'),
					'plugins' => getOptionsLike('_plugin_')
			);

			$adminTableDB = db_list_fields('administrators');
			$adminTable = array();
			foreach ($adminTableDB as $key => $datum) {
				// remove don't care fields
				unset($datum['Key']);
				unset($datum['Extra']);
				unset($datum['Privileges']);
				$adminTable[$datum['Field']] = $datum;
			}
			$_SESSION['admin']['db_admin_fields'] = $adminTable;
			$_SESSION['admin'][$cloneid] = serialize($_current_admin_obj);
			//	leave as direct link incase the admin mod_rewrite mechanism is not yet setup
			$msg[] = get_npgButton('button', gettext('setup the new install'), array('buttonClick' => 'window.open(\'' . $newinstall . CORE_FOLDER . '/setup/index.php?autorun\');')) . '<br clear="all">';
		} else {
			$reinstall = '<p>' . sprintf(gettext('Before running setup for <code>%1$s</code> please reinstall the following setup files from the %2$s to this installation:'), $newinstall, NETPHOTOGRAPHICS_VERSION) .
							"\n" . '<ul>' . "\n";
			if (!empty($needs)) {
				foreach ($needs as $script) {
					$reinstall .= '<li>' . CORE_FOLDER . '/setup/' . $script . '</li>' . "\n";
				}
			}
			$reinstall .= '</ul></p>' . "\n";
			$msg[] = $reinstall;
		}
	} else {
		array_unshift($msg, '<h2>' . sprintf(gettext('Clone to <code>%s</code> failed'), $folder) . '</h2>');
	}
}
require_once(PLUGIN_SERVERPATH . 'clone/cloneTab.php');
?>