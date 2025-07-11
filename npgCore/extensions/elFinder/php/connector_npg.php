<?php

//	based on elFinder connector.minimal.php-dist

require_once(dirname(dirname(dirname(dirname(__FILE__)))) . '/admin-globals.php');
XSRFdefender('elFinder');
// elFinder autoload
require PLUGIN_SERVERPATH . 'elFinder/php/autoload.php';
// ===============================================
// Required for MySQL storage connector
// include_once CORE_SERVERPATH .  PLUGIN_FOLDER.'/elFinder/php/elFinderVolumeMySQL.class.php';
// Required for FTP connector support
// include_once CORE_SERVERPATH . PLUGIN_FOLDER.'/elFinder/php/elFinderVolumeFTP.class.php';
// Required for Dropbox.com connector support
// include_once dirname(__FILE__).DIRECTORY_SEPARATOR.'elFinderVolumeDropbox.class.php';
// # Dropbox volume driver need "dropbox-php's Dropbox" and "PHP OAuth extension" or "PEAR's HTTP_OAUTH package"
// * dropbox-php: http://www.dropbox-php.com/
// * PHP OAuth extension: http://pecl.php.net/package/oauth
// * PEAR�s HTTP_OAUTH package: http://pear.php.net/package/http_oauth
//  * HTTP_OAUTH package require HTTP_Request2 and Net_URL2
// Dropbox driver need next two settings. You can get at https://www.dropbox.com/developers
// define('ELFINDER_DROPBOX_CONSUMERKEY',    '');
// define('ELFINDER_DROPBOX_CONSUMERSECRET', '');

/**
 * Simple function to demonstrate how to control file access using "accessControl" callback.
 * This method will disable accessing files/folders starting from  '.' (dot)
 *
 * @param  string  $attr  attribute name (read|write|locked|hidden)
 * @param  string  $path  file path relative to volume root directory started with directory separator
 * @return bool|null
 * */
function access($attr, $path, $data, $volume) {
	return strpos(basename($path), '.') === 0 // if file/folder begins with '.' (dot)
					? !($attr == 'read' || $attr == 'write' ) // set read+write to false, other (locked+hidden) set to true
					: null; // else elFinder decide it itself
}

function accessImage($attr, $path, $data, $volume) {
	global $validSuffix;
	if ($attr == 'write') {
		if (getAlbumFolder(SERVERPATH) == str_replace('\\', '/', $path) . '/' && $attr == 'write') {
			//	block if write to root album folder
			return false;
		}
	}
	if (access($attr, $path, $data, $volume)) {
		return true;
	}
	//	allow only images
	if (!is_dir($path) && !in_array(getSuffix($path), $validSuffix)) {
		return !($attr == 'read' || $attr == 'write');
	}
	return NULL;
}

function accessMedia($attr, $path, $data, $volume) {
	if (access($attr, $path, $data, $volume)) {
		return true;
	}
	//allow only tinyMCE recognized media suffixes
	$valid = array("mp3", "wav", "mp4", "webm", "ogg", "swf");
	if (!is_dir($path) && !in_array(getSuffix($path), $valid)) {
		return !($attr == 'read' || $attr == 'write');
	}
	return NULL;
}

function accessAlbums($attr, $path, $data, $volume) {
	//	restrict access to his albums
	$base = explode('/', str_replace(getAlbumFolder(SERVERPATH), '', str_replace('\\', '/', $path) . '/'));
	$base = reset($base);
	$block = !$base && $attr == 'write';
	if ($block || access($attr, $path, $data, $volume)) {
		return !($attr == 'read' || $attr == 'write');
	}
	return NULL;
}

$opts = array();
$rights = npg_loggedin();
$sidecars = npgFilters::apply('upload_filetypes', array());
$validSuffix = array_keys($_images_classes);
$validSuffix = array_merge($validSuffix, $sidecars);

$themeRequest = $albumRequest = false;
if ($_REQUEST['origin'] == 'upload') {
	$themeAlias = sprintf(gettext('Themes (%s)'), THEMEFOLDER);
	if (isset($_REQUEST['themeEdit'])) {
		$rights = 0;
		$themeRequest = sanitize($_REQUEST['themeEdit']);
		if (npg_loggedin(THEMES_RIGHTS) && file_exists(SERVERPATH . '/' . THEMEFOLDER . '/' . $themeRequest)) {
			if (!protectedTheme($themeRequest)) {
				$themeAlias = sprintf(gettext('%s'), $themeRequest);
				$themeRequest .= '/';
				$rights = THEMES_RIGHTS;
			}
		}
	} else {
		if (isset($_REQUEST['albumEdit'])) {
			$rights = 0;
			$albumRequest = sanitize($_REQUEST['albumEdit']);
			if (npg_loggedin(ALBUM_RIGHTS)) {
				$albumAlias = $albumRequest;
				$albumRequest .= '/';
				$rights = ALBUM_RIGHTS;
			}
		}
	}

	if (CASE_INSENSITIVE) { //	ignore case on case insensitive file systems!
		$i = 'i';
	} else {
		$i = '';
	}

	if ($rights & FILES_RIGHTS) {
		$opts['roots'][0] = array(
				'driver' => 'LocalFileSystem',
				'startPath' => SERVERPATH . '/' . UPLOAD_FOLDER . '/',
				'path' => SERVERPATH . '/' . UPLOAD_FOLDER . '/',
				'URL' => WEBPATH . '/' . UPLOAD_FOLDER . '/',
				'alias' => sprintf(gettext('Upload folder (%s)'), UPLOAD_FOLDER),
				'mimeDetect' => 'internal',
				'tmbPath' => '.tmb',
				'utf8fix' => true,
				'tmbCrop' => false,
				'tmbBgColor' => 'transparent',
				'accessControl' => 'access',
				'acceptedName' => '/^[^\.].*$/'
		);
	}

	if ($rights & THEMES_RIGHTS) {
		$theme_list = array();
		foreach ($_gallery->getThemes() as $theme => $data) {
			if (protectedTheme($theme)) {
				$theme_list[] = preg_quote($theme);
			}
		}
		$opts['roots'][1] = array(
				'driver' => 'LocalFileSystem',
				'startPath' => SERVERPATH . '/' . THEMEFOLDER . '/' . $themeRequest,
				'path' => SERVERPATH . '/' . THEMEFOLDER . '/' . $themeRequest,
				'URL' => WEBPATH . '/' . THEMEFOLDER . '/' . $themeRequest,
				'alias' => $themeAlias,
				'mimeDetect' => 'internal',
				'tmbPath' => '.tmb',
				'utf8fix' => true,
				'tmbCrop' => false,
				'tmbBgColor' => 'transparent',
				'accessControl' => 'access',
				'acceptedName' => '/^[^\.].*$/',
				'attributes' => array(
						array(
								'pattern' => '/.(' . implode('$|', $theme_list) . '$)/' . $i, // Dont write or delete to this but subfolders and files
								'read' => true,
								'write' => false,
								'locked' => true
						),
						array(
								'pattern' => '/.(' . implode('\/|', $theme_list) . '\/)/' . $i, // Dont write or delete to this but subfolders and files
								'read' => true,
								'write' => false,
								'locked' => true
						)
				)
		);
	}

	if ($albumRequest) { //	"upload here"
		$hide_list = $edit_list = array();

		$album = newAlbum($albumAlias);
		foreach ($album->getImages(0) as $key => $file) {
			$edit_list[] = preg_quote($file);
		}

		$junkFiles = safe_glob(getAlbumFolder(SERVERPATH) . '/' . $albumRequest . '*', GLOB_MARK);
		foreach ($junkFiles as $key => $path) {
			$file = preg_quote(basename($path));
			if (!in_array($file, $edit_list)) {
				$hide_list[] = $file;
			}
		}

		$opts['roots'][1] = array(
				'driver' => 'LocalFileSystem',
				'startPath' => getAlbumFolder(SERVERPATH) . '/' . $albumRequest,
				'path' => getAlbumFolder(SERVERPATH) . '/' . $albumRequest,
				'URL' => getAlbumFolder(WEBPATH) . '/' . $albumRequest,
				'alias' => $albumAlias,
				'mimeDetect' => 'internal',
				'tmbPath' => '.tmb',
				'utf8fix' => true,
				'tmbCrop' => false,
				'tmbBgColor' => 'transparent',
				'accessControl' => 'accessImage',
				'acceptedName' => '/^[^\.].*$/',
				'attributes' => array(
						array(
								'pattern' => '/.(' . implode('$|', $edit_list) . '$)/' . $i, // Dont write or delete to this but subfolders and files
								'read' => true,
								'write' => false,
								'locked' => true
						),
						array(
								'pattern' => '/.(' . implode('\/|', $edit_list) . '\/)/' . $i, // Dont write or delete to this but subfolders and files
								'read' => true,
								'write' => false,
								'locked' => true
						),
						array(
								'pattern' => '/.(' . implode('$|', $hide_list) . '$)/' . $i, // Dont write or delete to this but subfolders and files
								'read' => false,
								'write' => false,
								'hidden' => true,
								'locked' => true
						),
						array(
								'pattern' => '/.(' . implode('\/|', $hide_list) . '\/)/' . $i, // Dont write or delete to this but subfolders and files
								'read' => false,
								'write' => false,
								'hidden' => true,
								'locked' => true
						)
				)
		);
	}

	if ($rights & UPLOAD_RIGHTS) {
		$opts['roots'][2] = array(
				'driver' => 'LocalFileSystem',
				'startPath' => getAlbumFolder(SERVERPATH),
				'path' => getAlbumFolder(SERVERPATH),
				'URL' => getAlbumFolder(WEBPATH),
				'alias' => sprintf(gettext('Albums folder (%s)'), basename(getAlbumFolder())),
				'mimeDetect' => 'internal',
				'tmbPath' => '.tmb',
				'utf8fix' => true,
				'tmbCrop' => false,
				'tmbBgColor' => 'transparent',
				'uploadAllow' => array('image'),
				'acceptedName' => '/^[^\.].*$/'
		);
		if ($rights & (ADMIN_RIGHTS | MANAGE_ALL_ALBUM_RIGHTS)) {
			$opts['roots'][2]['accessControl'] = 'access';
		} else {
			$opts['roots'][0]['uploadDeny'] = array('text/x-php', 'application');
			$opts['roots'][2]['uploadDeny'] = array('text/x-php', 'application');
			if ($rights & FILES_RIGHTS) {
				$opts['roots'][2]['accessControl'] = 'accessAlbums';
			} else {
				$opts['roots'][2]['disabled'] = array('zipdl');	 // Disable downloads
				$opts['roots'][2]['accessControl'] = 'accessImage';
			}

			$_managed_folders = getManagedAlbumList();
			$excluded_folders = $_gallery->getAlbums(0, null, null, false, true); //	get them all!
			$excluded_folders = array_diff($excluded_folders, $_managed_folders);
			foreach ($excluded_folders as $key => $folder) {
				$excluded_folders[$key] = preg_quote($folder);
			}

			$junkFiles = safe_glob(getAlbumFolder() . '*.*');
			foreach ($junkFiles as $key => $path) {
				if (is_dir($path) || hasDynamicAlbumSuffix($path) || in_array(getSuffix($path), $sidecars)) {
					unset($junkFiles[$key]);
				} else {
					$junkFiles[$key] = preg_quote(basename($path));
				}
			}

			$maxupload = ini_get('upload_max_filesize');
			$maxuploadint = parse_size($maxupload);
			$uploadlimit = npgFilters::apply('get_upload_limit', $maxuploadint);
			$all_actions = $_not_upload = $_not_edit = array();

			foreach ($_managed_folders as $key => $folder) {
				$rightsalbum = newAlbum($folder);
				$modified_rights = $rightsalbum->subRights();
				if ($uploadlimit <= 0) {
					$modified_rights = $modified_rights & ~MANAGED_OBJECT_RIGHTS_UPLOAD;
				}
				$_not_edit[$key] = $_not_upload[$key] = $folder = preg_quote($folder);
				switch ($modified_rights & (MANAGED_OBJECT_RIGHTS_UPLOAD | MANAGED_OBJECT_RIGHTS_EDIT)) {
					case MANAGED_OBJECT_RIGHTS_UPLOAD: // upload but not edit
						unset($_not_upload[$key]);
						break;
					case MANAGED_OBJECT_RIGHTS_EDIT: // edit but not upload
						unset($_not_edit[$key]);
						break;
					case MANAGED_OBJECT_RIGHTS_UPLOAD | MANAGED_OBJECT_RIGHTS_EDIT: // edit and upload
						unset($_not_edit[$key]);
						unset($_not_upload[$key]);
						$all_actions[$key] = $folder;
						break;
				}
			}

			$excludepattern = '';
			$noteditpattern = '';
			foreach ($sidecars as $car) {
				$excludepattern .= '|' . implode('.' . $car . '|', $excluded_folders) . '.' . $car;
				$noteditpattern .= '|' . implode('.' . $car . '|', $_not_edit) . '.' . $car;
			}

			$opts['roots'][2]['attributes'] = array();

			if (!empty($junkFiles)) {
				$opts['roots'][2]['attributes'][] = array(// files in the album root that don't belong
						'pattern' => '/.(' . implode('$|', $junkFiles) . '$)/' . $i, // Dont write or delete
						'read' => false,
						'write' => false,
						'hidden' => true,
						'locked' => true
				);
			}

			if (!empty($excluded_folders)) {
				$opts['roots'][2]['attributes'][] = array(//	albums he does not manage
						'pattern' => '/.(' . implode('$|', $excluded_folders) . '$)/' . $i, // Dont write or delete to this but subfolders and files
						'read' => false,
						'write' => false,
						'hidden' => true,
						'locked' => true
				);

				$opts['roots'][2]['attributes'][] = array(//	sidecars for albums he does not manage
						'pattern' => '/.(' . ltrim($excludepattern, '|') . ')/i', // Dont write or delete to this but subfolders and files
						'read' => false,
						'write' => false,
						'hidden' => true,
						'locked' => true
				);
			}
			if (!empty($_not_upload)) {
				$opts['roots'][2]['attributes'][] = array(//	albums he can not upload
						'pattern' => '/.(' . implode('$|', $_not_upload) . '$)/' . $i, // Dont write or delete to this but subfolders and files
						'read' => true,
						'write' => false,
						'locked' => true
				);
			}
			if (!empty($_not_edit)) {
				$opts['roots'][2]['attributes'][] = array(//	albums content he not edit
						'pattern' => '/.(' . implode('\/|', $_not_edit) . '\/)/' . $i, // Dont write or delete to this but subfolders and files
						'read' => true,
						'write' => false,
						'locked' => true
				);
				$opts['roots'][2]['attributes'][] = array(//	sidecars for albums he can not edit
						'pattern' => '/.(' . ltrim($noteditpattern, '|') . ')/i', // Dont write or delete to this but subfolders and files
						'read' => true,
						'write' => false,
						'locked' => true
				);
			}
			if (!empty($all_actions)) {
				$opts['roots'][2]['attributes'][] = array(//	albums he can upload
						'pattern' => '/.(' . implode('$|', $all_actions) . '$)/' . $i, // Dont write or delete to this but subfolders and files
						'read' => true,
						'write' => true,
						'hidden' => false,
						'locked' => false
				);
			}
		}
	}

	if ($rights & ADMIN_RIGHTS) {
		$opts['roots'][3] = array(
				'driver' => 'LocalFileSystem',
				'startPath' => USER_PLUGIN_SERVERPATH,
				'path' => USER_PLUGIN_SERVERPATH,
				'URL' => WEBPATH . '/' . USER_PLUGIN_FOLDER . '/',
				'alias' => sprintf(gettext('Third party plugins (%s)'), USER_PLUGIN_FOLDER),
				'mimeDetect' => 'internal',
				'tmbPath' => '.tmb',
				'utf8fix' => true,
				'tmbCrop' => false,
				'tmbBgColor' => 'transparent',
				'accessControl' => 'access',
				'acceptedName' => '/^[^\.].*$/'
		);
		$opts['roots'][4] = array(
				'driver' => 'LocalFileSystem',
				'startPath' => SERVERPATH . '/' . DATA_FOLDER . '/',
				'path' => SERVERPATH . '/' . DATA_FOLDER . '/',
				'URL' => WEBPATH . '/' . DATA_FOLDER . '/',
				'alias' => sprintf(gettext('Data (%s)'), DATA_FOLDER),
				'mimeDetect' => 'internal',
				'tmbPath' => '.tmb',
				'utf8fix' => true,
				'tmbCrop' => false,
				'tmbBgColor' => 'transparent',
				'accessControl' => 'access',
				'acceptedName' => '/^[^\.].*$/'
		);
		$opts['roots'][5] = array(
				'driver' => 'LocalFileSystem',
				'startPath' => SERVERPATH . "/" . BACKUPFOLDER . '/',
				'path' => SERVERPATH . "/" . BACKUPFOLDER . '/',
				'URL' => WEBPATH . "/" . BACKUPFOLDER . '/',
				'alias' => sprintf(gettext('Backup files (%s)'), BACKUPFOLDER),
				'mimeDetect' => 'internal',
				'tmbPath' => '.tmb',
				'utf8fix' => true,
				'tmbCrop' => false,
				'tmbBgColor' => 'transparent',
				'accessControl' => 'access',
				'acceptedName' => '/^[^\.].*$/'
		);
	}
} else { //	origin == 'tinyMCE
	if ($rights & FILES_RIGHTS) {
		$opts['roots'][0] = array(
				'driver' => 'LocalFileSystem',
				'startPath' => SERVERPATH . '/' . UPLOAD_FOLDER . '/',
				'path' => SERVERPATH . '/' . UPLOAD_FOLDER . '/',
				'URL' => WEBPATH . '/' . UPLOAD_FOLDER . '/',
				'alias' => sprintf(gettext('Upload folder (%s)'), UPLOAD_FOLDER),
				'mimeDetect' => 'internal',
				'tmbPath' => '.tmb',
				'utf8fix' => true,
				'tmbCrop' => false,
				'tmbBgColor' => 'transparent',
				'uploadAllow' => array('image'),
				'accessControl' => 'accessImage',
				'acceptedName' => '/^[^\.].*$/',
				'uploadDeny' => array('text/x-php', 'text/html', 'application')
		);
		switch (isset($_GET['type']) ? $_GET['type'] : NULL) {
			case 'media':
				$opts['roots'][0]['accessControl'] = 'accessMedia';
				break;
			case 'image':
				$opts['roots'][0]['accessControl'] = 'accessImage';
				break;
			default:
				$opts['roots'][0]['accessControl'] = 'access';
				break;
		}
	}
}

// run elFinder
$connector = new elFinderConnector(new elFinder($opts));
$connector->run();

