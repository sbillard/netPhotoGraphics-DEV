<?php

/**
 * Uses <code>openstreetmap</code> to create a map Track image from a
 * <b>GPX</b> file.
 *
 * This plugin provides an image handler for <b>GPX</b> files.
 * A GPX file, or GPS Exchange Format file, is an XML file that stores geographic
 * information like Waypoints, Tracks, and Routes.
 * The "image" shown will be the map Track defined by the file.
 *
 * The plugin supports an extension to the standard <b>GPX</b> file to optionally
 * set the color of the Track. To specify the Track color insure that <code>gpxx</code>
 * namespace is defined as below in your <gpx> head tag and add a
 * <code>gpxx:DisplayColor</code> extension to the Track section.
 *
 * The default thumbnail was obtained from
 * {@link https://www.flaticon.com/free-icons/maps-and-location Maps and location icons created by Good Ware - Flaticon}.
 *
 * <block>
 * <gpx <i>xmlns:gpxx="http://www.garmin.com/xmlschemas/GpxExtensions/v3"</i>>
 * 	...
 * 	<trk>
 * 		<name>GraphHopper Track</name>
 * 		<i><extensions>
 * 		 	<gpxx:TrackExtension>
 * 		 	 	<gpxx:DisplayColor>Red</gpxx:DisplayColor>
 * 		 	</gpxx:TrackExtension>
 * 		</extensions></i>
 * 		<trkseg>
 * 			<trkpt lat="47.009857" lon="-113.075981"><ele>1298.6</ele></trkpt>
 * 			...
 * 			<trkpt lat="47.025194" lon="-113.063088"><ele>1313.8</ele></trkpt>
 * 		</trkseg>
 * 	 </trk>
 * </gpx>
 * </block>
 *
 *
 * @author Stephen Billard (sbillard)
 *
 * @package plugins/class-GPX
 * @pluginCategory media
 *
 */
$plugin_is_filter = 800 | CLASS_PLUGIN;
if (defined('SETUP_PLUGIN')) { //	gettext debugging aid
	$plugin_description = gettext('Treats GPX files as "images" and shows the map Track defined by the file.');
	$plugin_disable = extensionEnabled('openstreetmap') ? '' : gettext('class-GPX requires the openStreetMap plugin be enabled.');
}
$option_interface = 'GPX';

Gallery::addImageHandler('gpx', 'GPX');

require_once(__DIR__ . '/class-textobject/class-textobject_core.php');

class GPX extends TextObject_core {

	protected $GPXpath = array();
	protected $GPXpathName = '';
	protected $GPXpathColor;
	var $GPXwaypoints = array();

	function __construct($album = NULL, $filename = NULL, $quiet = false) {

		if (OFFSET_PATH == 2) {
			setOptionDefault('GPX_Track_color', 'blue');
			setOptionDefault('GPX_Route_color', 'green');
		}

		if (is_object($album)) {
			parent::__construct($album, $filename, $quiet);
		}
	}

	/**
	 * fetches the path color if it exists
	 *
	 * @param object $which
	 * @parm string $default
	 */
	private function getPathColor($which, $default) {
		if (!empty($which->extensions) && is_object($which->extensions->children('gpxx', true))) {
			return $which->extensions->children('gpxx', true)->TrackExtension->DisplayColor;
		}
		return getOption($default);
	}

	/**
	 * load the GPX data
	 */
	private function parseGPX() {

		$gpx = simplexml_load_file($this->localpath);

		if ($gpx !== false) {
			/* get track points */
			if (isset($gpx->trk)) {
				if (isset($gpx->trk->trkseg->trkpt)) {
					foreach ($gpx->trk->trkseg->trkpt as $trkpt) {
						$this->GPXpath[] = array(
								'lat' => (string) $trkpt['lat'],
								'long' => (string) $trkpt['lon'],
								'title' => 'Track Point',
								'desc' => '',
								'thumb' => '',
								'current' => 0
						);
					}
				}
				if (isset($gpx->trk->name)) {
					$this->GPXpathName = $gpx->trk->name;
				}
				$this->GPXpathColor = self::getPathColor($gpx->trk, 'GPX_Track_color');
			} else {
				/* 	get route points */
				if (isset($gpx->rte)) {
					foreach ($gpx->rte->rtept as $rtept) {
						$this->GPXpath[] = array(// we will treate routes as if they were tracks
								'lat' => (string) $rtept['lat'],
								'long' => (string) $rtept['lon'],
								'title' => 'Track Point',
								'desc' => '',
								'thumb' => '',
								'current' => 0
						);
					}
					if (isset($gpx->rte->name)) {
						$this->GPXpathName = $gpx->rte->name;
					}

					$this->GPXpathColor = self::getPathColor($gpx->rte, 'GPX_Route_color');
				}
			}
			if (empty($this->GPXpathColor)) {
				$this->GPXpathColor = 'black';
			}
			/* get waypoints */
			foreach ($gpx->wpt as $wpt) {
				if (isset($wpt->name)) {
					$name = (string) $wpt->name;
				} else {
					$name = '';
				}
				if (isset($wpt->desc)) {
					$desc = (string) $wpt->desc;
				} else {
					$desc = '';
				}
				if (isset($wpt->type)) {
					$type = (string) $wpt->type;
				} else {
					$type = '';
				}
				$this->GPXwaypoints[] = array(
						'lat' => (string) $wpt['lat'],
						'long' => (string) $wpt['lon'],
						'name' => $name,
						'desc' => $desc,
						'type' => $type
				);
			}
		} else {
			$this->exists = false;
			trigger_error(sprintf(gettext('%1$s: Failed to load GPX file.'), $this->displayname));
		}
	}

	/**
	 * Standard option interface
	 *
	 * @return array
	 */
	function getOptionsSupported() {
		return array(
				gettext('Default color for Tracks') => array('key' => 'GPX_Track_color',
						'type' => OPTION_TYPE_TEXTBOX,
						'desc' => sprintf(gettext('Track paths will be %1$s by default.'), getOption('GPX_Track_color'))),
				gettext('Default color for Routes') => array('key' => 'GPX_Route_color',
						'type' => OPTION_TYPE_TEXTBOX,
						'desc' => sprintf(gettext('Route paths will be %1$s by default.'), getOption('GPX_Route_color')))
		);
	}

	/**
	 * Returns the image file name for the thumbnail image.
	 *
	 * @return string
	 */
	function getThumbImageFile() {
		global $_gallery;
		if (is_null($this->objectsThumb)) {
			$img = '/' . getSuffix($this->filename) . 'Default.png';
			$imgfile = SERVERPATH . '/' . THEMEFOLDER . '/' . internalToFilesystem($_gallery->getCurrentTheme()) . '/images/' . $img;
			if (!file_exists($imgfile)) {
				$imgfile = SERVERPATH . "/" . USER_PLUGIN_FOLDER . '/' . substr(basename(__FILE__), 0, -4) . $img;
				if (!file_exists($imgfile)) {
					$imgfile = SERVERPATH . "/" . CORE_FOLDER . '/' . PLUGIN_FOLDER . '/' . substr(basename(__FILE__), 0, -4) . $img;
				}
			}
		} else {
			$imgfile = dirname($this->localpath) . '/' . $this->objectsThumb;
		}
		return $imgfile;
	}

	/**
	 * Returns the "image" html for the track
	 *
	 * @param type $w optional width
	 * @param type $h optional height
	 * @return type
	 */
	function getContent($w = NULL, $h = NULL) {

		self::parseGPX();

		if (empty($this->GPXpath)) {
			trigger_error(sprintf(gettext('%1$s: No GPX path'), $this->displayname));
		}

		$this->updateDimensions();
		if (is_null($w)) {
			$w = $this->getWidth();
		}
		if (is_null($h)) {
			$h = $this->getHeight();
		}

		$map = new openStreetMap($this->GPXpath, $this);

		$map->class = $map->mapid = 'osm_poly';
		$map->polycolor = $this->GPXpathColor;
		$map->mode = 'polyline-cluster';
		$map->hide = false;
		$map->width = $w . 'px';
		$map->height = $h . 'px';

		ob_start();
		$map->printMap();
		$img = ob_get_clean();

		return ($img);
	}

}
