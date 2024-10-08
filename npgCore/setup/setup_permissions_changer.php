<?php

/**
 * Used for changing permissions on a mass basis
 *
 * @author Stephen Billard (sbillard)
 *
 * @package setup
 *
 */
define('OFFSET_PATH', 2);
require_once(dirname(__DIR__) . '/functions.php');
require_once(__DIR__ . '/setup-functions.php');
if (!isset($_POST['folder'])) {
	exit();
}
$folder = rtrim(sanitize($_POST['folder'], 3), '/');

if ($_POST['key'] == sha1(filemtime(SERVERPATH . '/' . DATA_FOLDER . '/' . CONFIGFILE) . file_get_contents(SERVERPATH . '/' . DATA_FOLDER . '/' . CONFIGFILE))) {
	if (folderPermissions($folder)) {
		setupLog(sprintf(gettext('Setting permissions (0%o) for %s.'), FILE_MOD, basename($folder)), true);
	} else {
		setupLog(sprintf(gettext('Notice: failed setting permissions (0%o) for %s.'), FILE_MOD, basename($folder)), true);
	}
} else {
	setupLog(sprintf(gettext('Notice: illegal call for permissions setting for %s.'), basename($folder)), true);
}

function folderPermissions($folder) {
	$files = array();
	if (($dir = opendir($folder)) !== false) {
		while (($file = readdir($dir)) !== false) {
			if ($file != '.' && $file != '..') {
				$files[] = $file;
			}
		}
		closedir($dir);
	}
	foreach ($files as $file) {
		$path = $folder . '/' . $file;
		if (is_dir($path)) {
			chmod($path, FOLDER_MOD);
			if (checkPermissions(fileperms($path) & 0777, FOLDER_MOD)) {
				if (!folderPermissions($path)) {
					return false;
				}
			} else {
				return false;
			}
		} else {
			chmod($path, FILE_MOD);
			if (!checkPermissions(fileperms($path) & 0777, FILE_MOD)) {
				return false;
			}
		}
	}
	return true;
}

?>