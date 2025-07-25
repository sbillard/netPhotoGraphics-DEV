<?php
/**
 *
 * Used to cache Theme pages (i.e. those pages launched by the index.php script.)
 *
 * Exceptions to this are the <var>password.php</var> and <var>404.php</var> pages, any page listed in the
 * <i>Excluded pages</i> option, and any page whose script makes a call on the
 * <var>static_cache_html::disable()</var> function. <b>NOTE:</b> this function only prevents the
 * creation of a cache image of the page being viewed. If there is already an existing
 * cached page and none of the other exclusions are in effect, the cached page will be
 * shown.
 *
 * Caching is also aborted when the page being rendered is not static. For instance
 * pages containing a link to the image processor will not be cached so that the
 * image may be cached and the link changed to the cache folder. Similarly, pages
 * which contain comment forms are not cached because then the comment would never show.
 *
 * In addition, caching does not occur for pages viewed by logged-in users if the user has
 * <var>ADMIN</var> privileges or if he is the manager of an album being viewed or whose images are
 * being viewed. Likewise, Zenpage News and Pages are not cached when viewed by the author.
 *
 * @author Malte Müller (acrylian), Stephen Billard (sbillard)
 *
 * @package plugins/static_html_cache
 * @pluginCategory admin
 */
$plugin_is_filter = 400 | CLASS_PLUGIN;
if (defined('SETUP_PLUGIN')) { //	gettext debugging aid
	$plugin_description = gettext("Adds static HTML cache functionality.");
	$plugin_notice = TESTING_MODE ? gettext('Caching is disabled because <em>TESTING_MODE</em> is enabled.') : '';
}

$option_interface = 'static_html_cache_options';

$cache_path = SERVERPATH . '/' . STATIC_CACHE_FOLDER . "/";
if (!file_exists($cache_path)) {
	if (!mkdir($cache_path, FOLDER_MOD)) {
		die(gettext("Static HTML Cache folder could not be created. Please try to create it manually via FTP with chmod 0777."));
	}
}
$cachesubfolders = array("albums", "images", "pages");
foreach ($cachesubfolders as $cachesubfolder) {
	$cache_folder = $cache_path . $cachesubfolder . '/';
	if (!file_exists($cache_folder)) {
		if (!mkdir($cache_folder, FOLDER_MOD)) {
			die(gettext("Static HTML Cache folder could not be created. Please try to create it manually via FTP with chmod 0777."));
		}
	}
}

if (OFFSET_PATH == 2) { //	clear the cache upon upgrade
	static_html_cache::clearHTMLCache();
}

if (!TESTING_MODE) {
	$_HTML_cache = new static_html_cache();
	npgFilters::register('image_processor_uri', 'static_html_cache::_disable');
}

class static_html_cache_options {

	function __construct() {
		setOptionDefault('static_cache_expire', 86400);
		setOptionDefault('static_cache_excludedpages', 'search.php/,contact.php/,register.php/,favorites.php/');
	}

	function getOptionsSupported() {
		return array(gettext('Static HTML cache expire') => array('key' => 'static_cache_expire', 'type' => OPTION_TYPE_NUMBER,
						'desc' => gettext("When the cache should expire in seconds. Default is 86400 seconds (1 day  = 24 hrs * 60 min * 60 sec).")),
				gettext('Excluded pages') => array('key' => 'static_cache_excludedpages', 'type' => OPTION_TYPE_CLEARTEXTAREA,
						'desc' => gettext("The list of pages to be excluded from cache generation. Pages that can be excluded are custom theme pages including Zenpage pages (these optionally more specific by titlelink) and the standard theme files image.php (optionally by image file name), album.php (optionally by album folder name) or index.php.<br /> If you want to exclude a page completely enter <em>page-filename.php/</em>. <br />If you want to exclude a page by a specific title, image filename, or album folder name enter <em>pagefilename.php/titlelink or image filename or album folder</em>. Separate several entries by comma.")),
		);
	}

	function handleOption($option, $currentValue) {

	}

}

class static_html_cache {

	public $enabled = true; // manual disable caching a page
	private $pageCachePath = NULL;
	private $dirty;

	/**
	 * Checks if the current page should be excluded from caching.
	 * Pages that can be excluded are custom pages included Zenpage pages (these optionally more specific by titlelink)
	 * and the standard theme pages image.php (optionally by image file name), album.php (optionally by album folder name)
	 * or index.php
	 *
	 * @return bool
	 *
	 */
	function checkIfAllowedPage() {
		global $_gallery_page, $_current_image, $_current_album, $_CMS_current_page,
		$_CMS_current_article, $_current_admin_obj, $_CMS_current_category, $_authority;
		if (npg_loggedin(ADMIN_RIGHTS)) { // don't cache for admin
			return false;
		}
		switch ($_gallery_page) {
			case "image.php": // does it really makes sense to exclude images and albums?
				$obj = $_current_album;
				$title = $_current_image->filename;
				break;
			case "album.php":
				$obj = $_current_album;
				$title = $_current_album->name;
				break;
			case 'pages.php':
				$obj = $_CMS_current_page;
				$title = $_CMS_current_page->getTitlelink();
				break;
			case 'news.php':
				if (in_context(ZENPAGE_NEWS_ARTICLE)) {
					$obj = $_CMS_current_article;
					$title = $obj->getTitlelink();
				} else {
					if (in_context(ZENPAGE_NEWS_CATEGORY)) {
						$obj = $_CMS_current_category;
						$title = $obj->getTitlelink();
					} else {
						$obj = NULL;
						$title = NULL;
					}
				}
				break;
			default:
				$obj = NULL;
				if (isset($_GET['title'])) {
					$title = sanitize($_GET['title']);
				} else {
					$title = "";
				}
				break;
		}


		if ($obj && $obj->isMyItem($obj->manage_some_rights)) { // user is admin to this object--don't cache!
			return false;
		}
		$accessType = checkAccess();
		if ($accessType) {
			if (is_numeric($accessType)) {
				$accessType = 'user_auth';
			} else if ($accessType == 'public_access' && count($_authority->getAuthCookies()) > 0) {
				$accessType .= '1'; // logged in some sense
			}
		} else {
			return false; // visitor is going to get a password request--don't cache or that won't happen
		}

		if ($l = getOption('static_cache_excludedpages')) {
			$excludeList = explode(",", $l);
			foreach ($excludeList as $item) {
				$page_to_exclude = explode("/", $item);
				if ($_gallery_page == trim($page_to_exclude[0])) {
					$exclude = trim($page_to_exclude[1]);
					if (empty($exclude) || $title == $exclude) {
						return false;
					}
				}
			}
		}
		return $accessType;
	}

	/**
	 * Starts the caching: Gets either an already cached file if existing or starts the output buffering.
	 *
	 */
	function startHTMLCache() {
		global $_gallery_page, $_Script_processing_timer;
		if ($this->enabled && $accessType = $this->checkIfAllowedPage()) {
			$_Script_processing_timer['static cache start'] = microtime();
			$cachefilepath = $this->createCacheFilepath($accessType);
			if (!empty($cachefilepath)) {
				$cachefilepath = SERVERPATH . '/' . STATIC_CACHE_FOLDER . "/" . $cachefilepath;
				if (file_exists($cachefilepath) && $lastmodified = @filemtime($cachefilepath)) {
					// don't use cache if comment is posted or cache has expired
					if (time() - $lastmodified < getOption("static_cache_expire")) {
						if ($content = @file_get_contents($cachefilepath)) {

							//send the headers!
							header('Content-Type: text/html; charset=' . LOCAL_CHARSET);
							header("HTTP/1.0 200 OK");
							header("Status: 200 OK");
							header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $lastmodified) . ' GMT');

							echo $content;

							// cache statistics
							list($usec, $sec) = explode(' ', $_Script_processing_timer['start']);
							$start = (float) $usec + (float) $sec;
							list($usec, $sec) = explode(' ', $_Script_processing_timer['static cache start']);
							$start_cache = (float) $usec + (float) $sec;
							list($usec, $sec) = explode(' ', microtime());
							$end = (float) $usec + (float) $sec;
							echo "<!-- " . sprintf(gettext('Cached content of %3$s served by static_html_cache in %1$.4f seconds plus %2$.4f seconds unavoidable overhead.'), $end - $start_cache, $start_cache - $start, date('D, d M Y H:i:s', filemtime($cachefilepath))) . " -->\n";
							exit();
						}
					}
					$this->deletestatic_html_cacheFile($cachefilepath);
				}
				if (ob_start()) {
					$this->pageCachePath = $cachefilepath;
				}
			}
			unset($_Script_processing_timer['static cache start']); // leave it out of the summary page
		}
	}

	/**
	 * Ends the caching: Ends the output buffering  and writes the html cache file from the buffer
	 *
	 */
	function endHTMLCache() {
		global $_Script_processing_timer, $_image_need_cache;
		$cachefilepath = $this->pageCachePath;
		if (!empty($cachefilepath)) {
			$pagecontent = ob_get_clean();
			if ($this->enabled && $fh = fopen($cachefilepath, "w")) {
				fputs($fh, $pagecontent);
				fclose($fh);
			}
			$this->pageCachePath = NULL;
			echo $pagecontent;

			//Handle processing uncached images found
			if (!empty($_image_need_cache)) {
				?>
				<script>
					var needsCache = ["<?php echo implode('","', array_unique($_image_need_cache)); ?>"];
					var i, value;
					for (i in needsCache) {
						value = needsCache[i];
						$.ajax({
							cache: false,
							type: "GET",
							url: value
						});
					}
				</script>
				<?php
				$_image_need_cache = array();
			}
		}
	}

	/**
	 *
	 * Aborts HTML caching
	 * Used for instance, when there is a 404 error or such
	 *
	 * @param bool $flush set to false to discard prior output
	 *
	 */
	function abortHTMLCache($flush) {
		$this->enabled = false;
		if (!empty($this->pageCachePath)) {
			$this->pageCachePath = NULL;
			if ($flush) {
				@ob_end_flush();
			} else {
				@ob_end_clean();
			}
		}
	}

	/**
	 * Creates the path and filename of the page to be cached.
	 *
	 * @return string
	 */
	function createCacheFilepath($accessType) {
		global $_current_image, $_current_album, $_gallery_page, $_authority,
		$_CMS_current_article, $_CMS_current_category, $_CMS_current_page, $_gallery, $_current_page, $_current_search;
		// just make sure these are really empty
		$cachefilepath = $_gallery->getCurrentTheme() . '_' . $accessType . '_';
		$album = "";
		$image = "";
		$searchfields = "";
		$words = "";
		$date = "";
		$title = ""; // zenpage support
		$category = ""; // zenpage support
		if (isset($_REQUEST['locale'])) {
			$locale = "_" . sanitize($_REQUEST['locale']);
		} else {
			$locale = "_" . getOption('locale');
		}
		switch ($_gallery_page) {
			case 'index.php':
				$cachesubfolder = "pages";
				$cachefilepath .= "index";
				break;
			case 'album.php':
			case 'image.php':
				$cachesubfolder = "albums";
				$album = $_current_album->name;
				if (isset($_current_image)) {
					$cachesubfolder = "images";
					$image = "-" . $_current_image->filename;
				}
				$cachefilepath .= $album . $image;
				if (in_context(SEARCH_LINKED)) {
					$cachefilepath .= '_search_' . stripcslashes($_current_search->codifySearchString());
				}
				break;
			case 'pages.php':
				$cachesubfolder = "pages";
				$cachefilepath .= 'page-' . $_CMS_current_page->getTitlelink();
				break;
			case 'news.php':
				$cachesubfolder = "pages";
				if (is_object($_CMS_current_article)) {
					$title = "-" . $_CMS_current_article->getTitlelink();
				}
				if (is_object($_CMS_current_category)) {
					$category = "_cat-" . $_CMS_current_category->getTitlelink();
				}
				$cachefilepath .= 'news' . $category . $title;
				break;
			default:
				// custom pages
				$cachesubfolder = "pages";
				$cachefilepath .= 'custom-' . stripSuffix($_gallery_page);
				break;
		}
		$cachefilepath .= "_" . (int) $_current_page;

		if (getOption('obfuscate_cache')) {
			$cachefilepath = sha1($locale . HASH_SEED . $cachefilepath);
		} else {
			// strip characters that cannot be in file names
			$cachefilepath = str_replace(array('<', '>', ':', '"', '/', '\\', '|', '?', '*'), '_', $cachefilepath) . $locale;
		}
		return $cachesubfolder . "/" . $cachefilepath . '.html';
	}

	/**
	 * Deletes a cache file
	 *
	 * @param string $cachefilepath Path to the cache file to be deleted
	 */
	function deletestatic_html_cacheFile($cachefilepath) {
		if (file_exists($cachefilepath)) {
			@chmod($cachefilepath, 0777);
			@unlink($cachefilepath);
		}
	}

	/**
	 * Cleans out the cache folder. (Adpated from the image cache)
	 *
	 * @param string $cachefolder the sub-folder to clean
	 */
	static function clearHTMLCache($folder = NULL) {
		if ($folder) {
			$cachesubfolders = array($folder);
		} else {
			$cachesubfolders = array("index", "albums", "images", "pages");
		}
		foreach ($cachesubfolders as $cachesubfolder) {
			if (is_dir(SERVERPATH . '/' . STATIC_CACHE_FOLDER . "/" . $cachesubfolder)) {
				npgFunctions::removeDir(SERVERPATH . '/' . STATIC_CACHE_FOLDER . "/" . $cachesubfolder, true);
			}
		}
	}

	/**
	 * used to disable cashing when the uri is an image processor uri
	 * @param string $uri
	 * @return string
	 */
	static function _disable($uri, $args, $album, $image) {
		global $_HTML_cache, $_image_need_cache;
		$_HTML_cache->enabled = false;
		$_image_need_cache[] = $uri;
		return $uri;
	}

	static function process_ipURIs() {
		global $_image_need_cache;
		if (!empty($_image_need_cache)) {
			?>
			<script>
				var needsCache = ["<?php echo implode('","', $_image_need_cache); ?>"];
				var i, value;
				for (i in needsCache) {
					value = needsCache[i];
					$.ajax({
						cache: false,
						type: "GET",
						url: value
					});
				}

			</script>
			<?php
		}
	}

}
?>