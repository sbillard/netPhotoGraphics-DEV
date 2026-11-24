<?php

/*
 * Atelier - blog and portfolio theme for netPhotoGraphics
 * Author: Martin Kroul
 * Built on the tested structure of the Nova theme and on the ideas of Zenpage.
 * Developed in collaboration with Claude (AI assistant by Anthropic).
 * Released under the GNU General Public License, version 2 or later,
 * like netPhotoGraphics.
 */

// force UTF-8 Ø


if (!OFFSET_PATH) {

    // options forced by the theme (avoid conflicts with plugins)
    setOption('comment_form_toggle', false, true);
    setOption('comment_form_pagination', false, true);
    setOption('tinymce_comments', null, true);
    setOption('user_logout_login_form', 1, true);
    setOption('gmap_display', 'show', true);

    // thumbnail sizes (runtime only, not stored in the database)
    // album pages use a masonry: thumbnails keep their aspect ratio (no cropping)
    setOption('thumb_size', 640, false);
    setOption('thumb_crop', 0, false);
    setOption('zpB_album_thumb_width', 800, false);
    setOption('zpB_album_thumb_height', 560, false);

    $zpB_shorten_title_size = 50;

    $_current_page_check = 'my_checkPageValidity';

    $_zenpage_news_enabled = class_exists('CMS') && hasNews();
    $_zenpage_pages_enabled = class_exists('CMS') && hasPages();
}

/**
 * Sub pages of the current page as one row of chips.
 * printPageMenu('list-sub') opens an extra nested <ul> for every item on pages deeper than level 2,
 * which pushed all items except the first one into a second row. The lists are flattened here.
 */
function atelier_printSubPages() {
    ob_start();
    printPageMenu('list-sub', '', '', 'pages-list', 'active');
    $html = trim(ob_get_clean());
    if ($html === '') {
        return;
    }
    $html = preg_replace('~</?ul[^>]*>~i', '', $html);
    $html = str_replace('<a href', '<a class="chip" href', $html);
    echo '<nav class="chip-bar chip-bar--pages"><ul class="chip-list">' . $html . '</ul></nav>';
}

/**
 * Search form with a translated placeholder.
 */
function atelier_printSearchForm() {
    printSearchForm(NULL, 'search', false, '', NULL, NULL, NULL, NULL, gettext('What are you looking for?'));
}

/**
 * Menu entry for the favorites. The plugin's printFavoritesURL() prints nothing for the list that is
 * currently displayed, which left an empty menu item on the favorites page.
 */
function atelier_printFavoritesMenu() {
    global $_myFavorites, $_gallery_page;
    if ($_gallery_page == 'favorites.php' && is_object($_myFavorites)) {
        $text = get_language_string(getOption('favorites_linktext'));
        $instance = $_myFavorites->instance;
        $display = $text . ($instance ? '[' . $instance . ']' : '');
        echo '<a href="' . html_encode($_myFavorites->getLink(NULL, $instance)) . '" class="favorite_link">' . html_encode($display) . '</a>';
    }
    printFavoritesURL();
}

/**
 * News categories as a row of labelled chips ("Categories: All news (72) | Photos (38) | ...").
 * Replaces printAllNewsCategories(), whose output is a plain list with an untranslated "articles" text.
 */
function atelier_printNewsCategories($label = true) {
    global $_CMS, $_CMS_current_category, $_gallery_page;
    if (!class_exists('CMS')) {
        return;
    }
    $items = $_CMS->getAllCategories();
    if (empty($items)) {
        return;
    }
    $isIndex = ($_gallery_page == 'news.php') && !is_NewsCategory() && !is_NewsArchive() && !is_NewsArticle();

    $save = $_CMS_current_category;
    $_CMS_current_category = NULL;
    $all = $_CMS->getArticles(0);
    $_CMS_current_category = $save;
    // the blog list leaves the references out, so the "All news" count must do the same
    $refs = atelier_refCategory();
    if ($refs !== '') {
        $skip = array();
        foreach (newCategory($refs)->getArticles(0) as $r) {
            $skip[$r['titlelink']] = true;
        }
        $all = array_filter($all, function ($a) use ($skip) { return !isset($skip[$a['titlelink']]); });
    }
    $total = count($all);

    echo '<nav class="chip-bar" aria-label="' . html_encode(gettext('Categories')) . '">';
    if ($label) {
        echo '<span class="chip-bar__label">' . html_encode(gettext('Categories')) . ':</span>';
    }
    echo '<ul class="chip-list">';
    echo '<li><a class="chip' . ($isIndex ? ' is-active' : '') . '" href="' . html_encode(getNewsIndexURL()) . '">' .
    html_encode(gettext('All news')) . ' <small>(' . $total . ')</small></a></li>';
    foreach ($items as $item) {
        $cat = newCategory($item['titlelink']);
        $count = count($cat->getArticles());
        if (!$count) {
            continue;
        }
        $active = is_object($_CMS_current_category) && $_CMS_current_category->getTitlelink() == $item['titlelink'];
        echo '<li><a class="chip' . ($active ? ' is-active' : '') . '" href="' . html_encode($cat->getLink()) . '">' .
        html_encode($cat->getTitle()) . ' <small>(' . $count . ')</small></a></li>';
    }
    echo '</ul></nav>';
}

/**
 * Boolean theme option with a fallback: options introduced in a newer version of the theme
 * have no stored value until the theme options page has been saved once.
 */
function atelier_option($key, $default = true) {
    $value = getOption($key);
    return ($value === NULL) ? $default : (bool) $value;
}

function my_checkPageValidity($request, $gallery_page, $page) {
    if (($gallery_page == 'gallery.php') || ($gallery_page == 'home.php')) {
        $gallery_page = 'index.php';
    }
    return checkPageValidity($request, $gallery_page, $page);
}

/**
 * Inline SVG icon (stroke style, inherits currentColor).
 */
function atelier_icon($name, $size = 18) {
    $paths = array(
        'map'     => '<path d="M12 21s-7-6.2-7-11a7 7 0 0 1 14 0c0 4.8-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/>',
        'comment' => '<path d="M21 12a8 8 0 0 1-11.6 7.1L4 20l1-4.6A8 8 0 1 1 21 12z"/>',
        'search'  => '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>',
        'info'    => '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
        'user'    => '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
        'login'   => '<path d="M15 4h4a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-4M10 8l-4 4 4 4M6 12h10" transform="rotate(180 12 12)"/>',
        'logout'  => '<path d="M9 4H5a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h4M16 8l4 4-4 4M20 12H9"/>',
        'up'      => '<path d="M6 15l6-6 6 6"/>',
        'menu'    => '<path d="M4 7h16M4 12h16M4 17h16"/>',
        'moon'    => '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
        'sun'     => '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
        'close'   => '<path d="M6 6l12 12M18 6L6 18"/>',
        'camera'  => '<path d="M4 8h3l1.5-2h7L17 8h3a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1z"/><circle cx="12" cy="13" r="3.5"/>',
        'lock'    => '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
        'heart'   => '<path d="M12 20s-7-4.4-7-10a4 4 0 0 1 7-2.6A4 4 0 0 1 19 10c0 5.6-7 10-7 10z"/>',
        'arrow'   => '<path d="M5 12h14M13 6l6 6-6 6"/>',
    );
    if (!isset($paths[$name])) {
        return '';
    }
    return '<svg class="icon" width="' . $size . '" height="' . $size . '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' . $paths[$name] . '</svg>';
}

/**
 * Gallery statistics for the footer.
 */
function atelier_getStats() {
    // cached for 6 hours - the counts are expensive on big galleries
    $cached = getOption('atelier_stats_cache');
    if ($cached) {
        $data = json_decode($cached, true);
        if (is_array($data) && isset($data['time']) && isset($data['albums']) && (time() - $data['time']) < 21600) {
            return $data;
        }
    }
    $data = atelier_computeStats();
    $data['time'] = time();
    setOption('atelier_stats_cache', json_encode($data), true);
    return $data;
}

function atelier_computeStats() {
    $row = query_single_row('SELECT count(*) FROM ' . prefix('images'));
    $total = (int) reset($row);

    $row = query_single_row('SELECT count(*) FROM ' . prefix('images') . ' WHERE `gpslatitude` IS NOT NULL AND `gpslongitude` IS NOT NULL');
    $gps = (int) reset($row);

    $row = query_single_row('SELECT count(*) FROM ' . prefix('images') .
            ' WHERE (`title` IS NOT NULL AND `title` != ""' .
            ' AND `title` != REPLACE(`filename`, ".jpg", "")' .
            ' AND `title` != REPLACE(`filename`, ".avif", "")' .
            ' AND `title` != REPLACE(`filename`, ".webp", "")' .
            ' AND `title` != REPLACE(`filename`, ".pdf", "")' .
            ' AND `title` != REPLACE(`filename`, ".docx", "")' .
            ' AND `title` != REPLACE(`filename`, ".mp4", ""))');
    $described = (int) reset($row);

    $count = function ($table, $where = '') {
        $r = query_single_row('SELECT count(*) FROM ' . prefix($table) . $where);
        return $r ? (int) reset($r) : 0;
    };
    $albums = $count('albums', ' WHERE `show` = 1');
    $pages = 0;
    $news = 0;
    if (extensionEnabled('zenpage')) {
        $pages = $count('pages', ' WHERE `show` = 1');
        $news = $count('news', ' WHERE `show` = 1');
    }
    $tags = $count('tags');

    $d = max($total, 1);
    return array(
        'albums' => $albums,
        'pages' => $pages,
        'news' => $news,
        'tags' => $tags,
        'total' => $total,
        'gps' => $gps,
        'gps_percent' => round($gps / $d * 100),
        'described' => $described,
        'described_percent' => round($described / $d * 100),
    );
}

/**
 * Does the current album contain at least one image with GPS coordinates?
 */
function atelier_albumHasGeodata() {
    global $_current_album;
    if (!is_object($_current_album) || !isImagePage()) {
        return false;
    }
    if (!$_current_album->isDynamic()) {
        $row = query_single_row('SELECT `id` FROM ' . prefix('images') .
                ' WHERE `albumid` = ' . (int) $_current_album->getID() .
                ' AND `gpslatitude` IS NOT NULL AND `gpslongitude` IS NOT NULL LIMIT 1');
        return !empty($row);
    }
    foreach ($_current_album->getImages() as $file) {
        $image = newImage($_current_album, $file);
        if (!empty($image->getGPSLatitude()) && !empty($image->getGPSLongitude())) {
            return true;
        }
    }
    return false;
}

/**
 * Source link of an online video embedded in a txt/htm/html file.
 */
function zpB_getLink($content) {
    $link = false;
    if (preg_match('/<iframe/', $content) && preg_match('/src="([^"]+)"/', $content, $result)) {
        $link = pathurlencode($result[1]);
    }
    return $link;
}

/* ------------------------------------------------------------------
 * Photo map page (photomap.php): server side helpers.
 * The map never receives all points at once. The browser asks for the
 * visible area only and the server answers with grid clusters (zoomed
 * out) or single points (zoomed in).
 * ------------------------------------------------------------------ */

/**
 * Albums the current visitor may not see (cached for 10 minutes in the session
 * because evaluating every album can be slow in big galleries).
 */
function atelier_geoHiddenAlbums() {
    if (npg_loggedin(ADMIN_RIGHTS | MANAGE_ALL_ALBUM_RIGHTS)) {
        return array();
    }
    $key = 'atelier_geo_hidden';
    if (isset($_SESSION[$key]) && is_array($_SESSION[$key]) && $_SESSION[$key]['t'] > time() - 600) {
        return $_SESSION[$key]['ids'];
    }
    $ids = array_map('intval', (array) getNotViewableAlbums());
    $_SESSION[$key] = array('t' => time(), 'ids' => $ids);
    return $ids;
}

/**
 * Derived table with numeric coordinates of every visible geotagged image.
 */
function atelier_geoSource() {
    $lat = "CAST(REPLACE(`gpslatitude`, ',', '.') AS DECIMAL(10,6))";
    $lon = "CAST(REPLACE(`gpslongitude`, ',', '.') AS DECIMAL(10,6))";
    $where = "`show` = 1 AND `gpslatitude` IS NOT NULL AND `gpslongitude` IS NOT NULL AND TRIM(`gpslatitude`) <> '' AND TRIM(`gpslongitude`) <> ''";
    $hidden = atelier_geoHiddenAlbums();
    if ($hidden) {
        $where .= ' AND `albumid` NOT IN (' . implode(',', $hidden) . ')';
    }
    if (!npg_loggedin(ADMIN_RIGHTS | MANAGE_ALL_ALBUM_RIGHTS)) {
        $where .= ' AND `albumid` IN (SELECT `id` FROM ' . prefix('albums') . ' WHERE `show` = 1)';
    }
    return '(SELECT `id`, ' . $lat . ' AS la, ' . $lon . ' AS lo FROM ' . prefix('images') . ' WHERE ' . $where . ') AS g';
}

/**
 * Overall numbers for the page (count and bounds of the visible geotagged images). Cached 1 hour.
 */
function atelier_geoMeta() {
    $key = 'guest';
    $cache = getOption('atelier_geo_meta_cache');
    $cache = $cache ? @unserialize($cache) : array();
    if (!is_array($cache)) {
        $cache = array();
    }
    if (isset($cache[$key]) && $cache[$key]['t'] > time() - 3600 && !npg_loggedin()) {
        return $cache[$key]['d'];
    }
    $row = query_single_row('SELECT COUNT(*) AS n, MIN(la) AS mila, MAX(la) AS mala, MIN(lo) AS milo, MAX(lo) AS malo FROM ' . atelier_geoSource() .
            ' WHERE la <> 0 AND lo <> 0 AND la BETWEEN -90 AND 90 AND lo BETWEEN -180 AND 180');
    $meta = array('n' => (int) ($row['n'] ?? 0), 'bounds' => null);
    if ($meta['n'] > 0) {
        $meta['bounds'] = array((float) $row['mila'], (float) $row['milo'], (float) $row['mala'], (float) $row['malo']);
    }
    if (!npg_loggedin()) {
        $cache[$key] = array('t' => time(), 'd' => $meta);
        setOption('atelier_geo_meta_cache', serialize($cache));
    }
    return $meta;
}

function atelier_geoJson($data, $maxAge = 0) {
    while (ob_get_level()) {
        ob_end_clean();
    }
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: ' . ($maxAge ? 'private, max-age=' . (int) $maxAge : 'no-store'));
    echo json_encode($data);
    exit;
}

/**
 * JSON endpoint. Called from photomap.php before any HTML is produced.
 *   ?atelier_geo=view&s=&w=&n=&e=&z=   clusters or points inside the view
 *   ?atelier_geo=items&s=&w=&n=&e=     up to 9 image previews inside a tiny box
 */
function atelier_geoEndpoint() {
    $mode = $_GET['atelier_geo'];
    $s = max(-90, min(90, (float) ($_GET['s'] ?? -90)));
    $n = max(-90, min(90, (float) ($_GET['n'] ?? 90)));
    $w = max(-180, min(180, (float) ($_GET['w'] ?? -180)));
    $e = max(-180, min(180, (float) ($_GET['e'] ?? 180)));
    if ($s > $n) {
        list($s, $n) = array($n, $s);
    }
    if ($w > $e) {
        list($w, $e) = array($e, $w);
    }
    $src = atelier_geoSource();
    $box = ' WHERE la BETWEEN ' . $s . ' AND ' . $n . ' AND lo BETWEEN ' . $w . ' AND ' . $e . ' AND la <> 0 AND lo <> 0';

    if ($mode === 'items') {
        $rows = query_full_array('SELECT `id` FROM ' . $src . $box . ' ORDER BY `id` DESC LIMIT 30');
        $total = (int) ((query_single_row('SELECT COUNT(*) AS n FROM ' . $src . $box)['n']) ?? 0);
        $items = array();
        foreach ((array) $rows as $r) {
            $img = atelier_geoImage((int) $r['id']);
            if (!$img) {
                continue;
            }
            $items[] = array(
                'title' => $img->getTitle(),
                'url' => $img->getLink(),
                'thumb' => $img->getCustomImage(array('width' => 200, 'height' => 200, 'cw' => 200, 'ch' => 200, 'thumb' => true)),
                'album' => $img->getAlbum()->getTitle(),
            );
            if (count($items) >= 9) {
                break;
            }
        }
        atelier_geoJson(array('total' => $total, 'items' => $items), 300);
    }

    // view
    $z = max(0, min(22, (int) ($_GET['z'] ?? 5)));
    $cap = 300;
    $n_in = (int) ((query_single_row('SELECT COUNT(*) AS n FROM ' . $src . $box)['n']) ?? 0);
    $out = array('total' => $n_in, 'pts' => array());
    // one code path: grid clusters; with few photos in view the grid is ~1 m, so every photo is its own point
    $cell = ($n_in <= $cap) ? 0.00001 : 60 * 360 / (256 * pow(2, $z));
    $rows = query_full_array('SELECT COUNT(*) AS c, AVG(la) AS avla, AVG(lo) AS avlo, MIN(la) AS mila, MAX(la) AS mala, MIN(lo) AS milo, MAX(lo) AS malo FROM ' . $src . $box .
            ' GROUP BY FLOOR(la / ' . $cell . '), FLOOR(lo / ' . $cell . ') LIMIT 2000');
    foreach ((array) $rows as $r) {
        $out['pts'][] = array(round((float) $r['avla'], 6), round((float) $r['avlo'], 6), (int) $r['c'],
            (float) $r['mila'], (float) $r['milo'], (float) $r['mala'], (float) $r['malo']);
    }
    atelier_geoJson($out, 300);
}

function atelier_geoImage($id) {
    $row = query_single_row('SELECT i.`filename`, a.`folder` FROM ' . prefix('images') . ' AS i JOIN ' . prefix('albums') . ' AS a ON a.`id` = i.`albumid` WHERE i.`id` = ' . (int) $id);
    if (!$row) {
        return false;
    }
    $album = newAlbum($row['folder'], true, true);
    if (!$album || !$album->exists) {
        return false;
    }
    $img = newImage($album, $row['filename'], true);
    if (!$img || !$img->exists || !$img->checkAccess()) {
        return false;
    }
    return $img;
}

/**
 * Load the Leaflet files shipped with the openStreetMap plugin (only the map core, no cluster plugin needed).
 */
function atelier_loadLeaflet() {
    $dir = PLUGIN_SERVERPATH . 'openstreetmap/';
    scriptLoader($dir . 'leaflet.css');
    scriptLoader($dir . 'leaflet.js');
}

function atelier_mapPageEnabled() {
    return (bool) atelier_option('zpB_show_map_page', false);
}

/* ------------------------------------------------------------------
 * Photos on the home page (random or latest). The candidate list is
 * built by one cheap query and cached, so the home page never runs a
 * slow "random image" search and the same few thumbnails are reused.
 * ------------------------------------------------------------------ */

/**
 * Most used tags (cached 6 hours, separately for guests and logged in users).
 */
function atelier_getTags($limit = 60) {
    $key = npg_loggedin() ? 'user' : 'guest';
    $cache = getOption('atelier_tagcloud_cache');
    $cache = $cache ? @unserialize($cache) : array();
    if (!is_array($cache)) {
        $cache = array();
    }
    if (isset($cache[$key]) && $cache[$key]['t'] > time() - 21600) {
        return $cache[$key]['tags'];
    }
    $tags = getAllTagsUnique(NULL, 1, true);
    $tags = is_array($tags) ? $tags : array();
    arsort($tags);
    $tags = array_slice($tags, 0, $limit, true);
    $cache[$key] = array('t' => time(), 'tags' => $tags);
    setOption('atelier_tagcloud_cache', serialize($cache));
    return $tags;
}

/**
 * Small gallery statistics and a tag cloud (bottom of the home page).
 */
function atelier_printHomeStats() {
    if (!atelier_option('zpB_home_stats', true)) {
        return;
    }
    $st = atelier_getStats();
    $items = array(
        array($st['total'], gettext('Images')),
        array($st['albums'], gettext('Albums')),
    );
    if ($st['pages'] > 0) {
        $items[] = array($st['pages'], gettext('Pages'));
    }
    if ($st['news'] > 0) {
        $items[] = array($st['news'], NEWS_LABEL);
    }
    if ($st['tags'] > 0) {
        $items[] = array($st['tags'], gettext('Tags'));
    }
    ?>
    <section class="home-stats">
        <ul class="stat-tiles">
            <?php foreach ($items as $it) { ?>
                <li><strong><?php echo number_format($it[0], 0, ',', '&nbsp;'); ?></strong><span><?php echo html_encode($it[1]); ?></span></li>
            <?php } ?>
        </ul>
        <?php
        $tags = atelier_getTags(60);
        if ($tags) {
            $min = min($tags);
            $max = max($tags);
            $keys = array_keys($tags);
            localeSort($keys);
            ?>
            <ul class="tag-cloud" aria-label="<?php echo gettext('Tags'); ?>">
                <?php
                foreach ($keys as $tag) {
                    $w = ($max > $min) ? sqrt(($tags[$tag] - $min) / ($max - $min)) : 0.5;
                    $size = round(0.85 + $w * 0.95, 2);
                    $link = SearchEngine::getURL(SearchEngine::searchQuote($tag), '', 'tags', 0, array('albums' => NULL));
                    ?>
                    <li><a href="<?php echo html_encode($link); ?>" rel="nofollow" style="font-size:<?php echo str_replace(',', '.', $size); ?>em" title="<?php echo (int) $tags[$tag]; ?>"><?php echo str_replace(' ', '&nbsp;', html_encode($tag)); ?></a></li>
                <?php } ?>
            </ul>
        <?php } ?>
    </section>
    <?php
}


/*
 * Lazy loading of thumbnails: a page with many photos asks the server only for the thumbnails
 * that are (nearly) visible instead of all of them at once. Fewer simultaneous requests, so a
 * hosting rate limit (429 Too Many Requests) is not triggered by opening a big album.
 */
function atelier_lazyThumb($html) {
    if (is_string($html) && strpos($html, 'loading=') === false) {
        $html = preg_replace('/<img\s/', '<img loading="lazy" decoding="async" ', $html, 1);
    }
    return $html;
}
npgFilters::register('standard_image_thumb_html', 'atelier_lazyThumb');
npgFilters::register('standard_album_thumb_html', 'atelier_lazyThumb');
npgFilters::register('custom_album_thumb_html', 'atelier_lazyThumb');


/* ==================================================================
 * Atelier: colour schemes, WCAG contrast helpers
 * ================================================================== */

function atelier_schemes() {
    return array(
        'terakota' => gettext('Terracotta'),
        'les' => gettext('Forest'),
        'ocean' => gettext('Ocean'),
        'svestka' => gettext('Plum'),
        'pisek' => gettext('Sand'),
        'grafit' => gettext('Graphite'),
        'bila' => gettext('White'),
    );
}

function atelier_scheme() {
    $s = getOption('atelier_scheme');
    if ($s === 'custom') {
        return 'custom';
    }
    $all = atelier_schemes();
    return isset($all[$s]) ? $s : 'bila';
}

/** 'auto' (follow the device), 'light' or 'dark' */
function atelier_mode() {
    $m = getOption('atelier_mode');
    return in_array($m, array('light', 'dark'), true) ? $m : 'auto';
}

function atelier_hex($hex) {
    $hex = ltrim(trim((string) $hex), '#');
    if (strlen($hex) === 3) {
        $hex = $hex[0] . $hex[0] . $hex[1] . $hex[1] . $hex[2] . $hex[2];
    }
    return preg_match('/^[0-9a-fA-F]{6}$/', $hex) ? strtolower($hex) : false;
}

function atelier_rgb($hex) {
    return array(hexdec(substr($hex, 0, 2)) / 255, hexdec(substr($hex, 2, 2)) / 255, hexdec(substr($hex, 4, 2)) / 255);
}

function atelier_luminance($hex) {
    $f = function ($c) {
        return $c <= 0.03928 ? $c / 12.92 : pow(($c + 0.055) / 1.055, 2.4);
    };
    list($r, $g, $b) = atelier_rgb($hex);
    return 0.2126 * $f($r) + 0.7152 * $f($g) + 0.0722 * $f($b);
}

function atelier_contrast($a, $b) {
    $la = atelier_luminance($a);
    $lb = atelier_luminance($b);
    if ($la < $lb) {
        list($la, $lb) = array($lb, $la);
    }
    return ($la + 0.05) / ($lb + 0.05);
}

function atelier_rgb2hsl($r, $g, $b) {
    $max = max($r, $g, $b);
    $min = min($r, $g, $b);
    $l = ($max + $min) / 2;
    if ($max == $min) {
        return array(0, 0, $l);
    }
    $d = $max - $min;
    $s = $l > 0.5 ? $d / (2 - $max - $min) : $d / ($max + $min);
    if ($max == $r) {
        $h = ($g - $b) / $d + ($g < $b ? 6 : 0);
    } elseif ($max == $g) {
        $h = ($b - $r) / $d + 2;
    } else {
        $h = ($r - $g) / $d + 4;
    }
    return array($h / 6, $s, $l);
}

function atelier_hsl2hex($h, $s, $l) {
    $hue = function ($p, $q, $t) {
        if ($t < 0) {
            $t += 1;
        }
        if ($t > 1) {
            $t -= 1;
        }
        if ($t < 1 / 6) {
            return $p + ($q - $p) * 6 * $t;
        }
        if ($t < 1 / 2) {
            return $q;
        }
        if ($t < 2 / 3) {
            return $p + ($q - $p) * (2 / 3 - $t) * 6;
        }
        return $p;
    };
    if ($s == 0) {
        $r = $g = $b = $l;
    } else {
        $q = $l < 0.5 ? $l * (1 + $s) : $l + $s - $l * $s;
        $p = 2 * $l - $q;
        $r = $hue($p, $q, $h + 1 / 3);
        $g = $hue($p, $q, $h);
        $b = $hue($p, $q, $h - 1 / 3);
    }
    return sprintf('%02x%02x%02x', round($r * 255), round($g * 255), round($b * 255));
}

/**
 * Nearest colour (same hue and saturation) that reaches the contrast on every given background.
 * @param string $hex colour (6 hex digits)
 * @param array $backgrounds hex colours the text colour must stand out from
 * @param float $min required ratio (4.5 = WCAG AA for text)
 * @param int $direction -1 darker, +1 lighter
 */
function atelier_fitColor($hex, $backgrounds, $min, $direction) {
    $ok = function ($c) use ($backgrounds, $min) {
        foreach ($backgrounds as $bg) {
            if (atelier_contrast($c, $bg) < $min) {
                return false;
            }
        }
        return true;
    };
    if ($ok($hex)) {
        return $hex;
    }
    list($h, $s, $l) = atelier_rgb2hsl(...atelier_rgb($hex));
    for ($i = 0; $i < 100; $i++) {
        $l = max(0, min(1, $l + $direction * 0.01));
        $c = atelier_hsl2hex($h, $s, $l);
        if ($ok($c)) {
            return $c;
        }
    }
    return $direction < 0 ? '000000' : 'ffffff';
}

/**
 * Colours derived from a custom accent: light and dark variant, both AA-safe.
 * @return array|false
 */
function atelier_customColors($input) {
    $hex = atelier_hex($input);
    if (!$hex) {
        return false;
    }
    $light = array('bg' => 'f6f5f2', 'surface' => 'ffffff', 's2' => 'eeede9');
    $dark = array('bg' => '141413', 'surface' => '1d1d1b', 's2' => '262624');
    $la = atelier_fitColor($hex, array_values($light), 4.5, -1);
    $da = atelier_fitColor($hex, array_values($dark), 4.5, +1);
    $res = array(
        'input' => $hex,
        'adjusted' => ($la !== $hex),
        'light' => array('accent' => $la, 'hover' => atelier_fitColor(atelier_hsl2hex(...array_merge(array_slice(atelier_rgb2hsl(...atelier_rgb($la)), 0, 2), array(max(0, atelier_rgb2hsl(...atelier_rgb($la))[2] - 0.09)))), array_values($light), 4.5, -1)),
        'dark' => array('accent' => $da, 'hover' => atelier_fitColor(atelier_hsl2hex(...array_merge(array_slice(atelier_rgb2hsl(...atelier_rgb($da)), 0, 2), array(min(1, atelier_rgb2hsl(...atelier_rgb($da))[2] + 0.10)))), array_values($dark), 4.5, +1)),
    );
    foreach (array('light', 'dark') as $m) {
        $a = $res[$m]['accent'];
        $res[$m]['on'] = (atelier_contrast('ffffff', $a) >= atelier_contrast('14110f', $a)) ? 'ffffff' : '14110f';
        $res[$m]['ratio'] = round(atelier_contrast($a, $m == 'light' ? $light['bg'] : $dark['bg']), 2);
    }
    return $res;
}

/** Inline CSS with the neutral base and the derived accent for the "custom" scheme. */
function atelier_customCss() {
    $c = atelier_customColors(getOption('atelier_custom_accent'));
    if (!$c) {
        $c = atelier_customColors('1b5d8f');
    }
    $css = ':root[data-scheme="custom"][data-theme="light"]{--bg:#f6f5f2;--surface:#ffffff;--surface-2:#eeede9;--text:#1c1c1b;--muted:#5e5e5a;--border:#dedcd6;--border-strong:#7e7c76;' .
            '--accent:#' . $c['light']['accent'] . ';--accent-hover:#' . $c['light']['hover'] . ';--on-accent:#' . $c['light']['on'] . ';--danger:#b3261e;--ok:#2e6b32}' .
            ':root[data-scheme="custom"][data-theme="dark"]{--bg:#141413;--surface:#1d1d1b;--surface-2:#262624;--text:#ecebe7;--muted:#aaa9a3;--border:#353532;--border-strong:#82817b;' .
            '--accent:#' . $c['dark']['accent'] . ';--accent-hover:#' . $c['dark']['hover'] . ';--on-accent:#' . $c['dark']['on'] . ';--danger:#f2877f;--ok:#7fcf84}';
    return $css;
}

/* ==================================================================
 * Content helpers (blog cards, references, home page)
 * ================================================================== */

/** First <img> of an HTML text: array(src, alt) or NULL. */
function atelier_firstImage($html) {
    if (!is_string($html) || !preg_match('~<img\b[^>]*>~i', $html, $m)) {
        return NULL;
    }
    $tag = $m[0];
    $src = '';
    // src, then the usual lazy-loading attributes, then the first srcset candidate
    foreach (array('src', 'data-src', 'data-lazy-src', 'data-original', 'srcset', 'data-srcset') as $attr) {
        if (preg_match('~\b' . preg_quote($attr, '~') . '\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))~i', $tag, $s)) {
            $v = trim($s[1] !== '' ? $s[1] : ($s[2] !== '' ? $s[2] : $s[3]));
            if ($attr === 'srcset' || $attr === 'data-srcset') {
                $v = trim(preg_split('~\s+~', trim(explode(',', $v)[0]))[0]);
            }
            if ($v !== '' && strpos($v, 'data:') !== 0) {
                $src = $v;
                break;
            }
        }
    }
    if ($src === '') {
        return NULL;
    }
    $alt = '';
    if (preg_match('~\balt\s*=\s*["\']([^"\']*)["\']~i', $tag, $a)) {
        $alt = html_entity_decode($a[1], ENT_QUOTES, 'UTF-8');
    }
    return array(html_entity_decode($src, ENT_QUOTES, 'UTF-8'), $alt);
}

/** Text without the first image (the small photo of a reference is shown separately). */
function atelier_withoutFirstImage($html) {
    $html = preg_replace('~<img\b[^>]*>~i', '', (string) $html, 1);
    return preg_replace('~<(p|a|div)[^>]*>\s*(&nbsp;|\s)*</\1>~i', '', $html);
}

function atelier_excerpt($html, $length = 190) {
    $text = trim(preg_replace('~\s+~u', ' ', html_entity_decode(strip_tags(preg_replace('~<(/?)(p|h[1-6]|li|br|div|blockquote|tr|td|th)\b~i', ' <$1$2', (string) $html)), ENT_QUOTES, 'UTF-8')));
    if (mb_strlen($text) <= $length) {
        return $text;
    }
    $cut = mb_substr($text, 0, $length);
    $sp = mb_strrpos($cut, ' ');
    return rtrim(($sp !== false && $sp > $length * 0.6) ? mb_substr($cut, 0, $sp) : $cut, " ,.;:-–") . '…';
}

/** Number of words -> "3 min" reading time. */
function atelier_readingTime($html) {
    $words = preg_split('~\s+~u', trim(strip_tags((string) $html)), -1, PREG_SPLIT_NO_EMPTY);
    return max(1, (int) ceil(count($words) / 200));
}

/**
 * One blog card.
 * @param object $obj article
 * @param string $size 'large' | 'small'
 */
function atelier_printStoryCard($obj, $size = 'small') {
    $content = $obj->getContent();
    $img = atelier_firstImage($content);
    $cats = array();
    foreach (sortByMultilingual($obj->getCategories(), 'title', false) as $cat) {
        $c = newCategory($cat['titlelink']);
        $cats[] = $c->getTitle();
    }
    $date = formattedDate(DATE_FORMAT, strtotime($obj->getDateTime()));
    $isLarge = ($size === 'large');
    ?>
    <article class="story story--<?php echo $size; ?><?php echo $img ? '' : ' story--noimg'; ?>">
        <a class="story__media" href="<?php echo html_encode($obj->getLink()); ?>" tabindex="-1" aria-hidden="true">
            <?php if ($img) { ?>
                <img loading="lazy" decoding="async" src="<?php echo html_encode($img[0]); ?>" alt="">
            <?php } else { ?>
                <span class="story__placeholder"><?php echo atelier_icon('camera', 36); ?></span>
            <?php } ?>
        </a>
        <div class="story__body">
            <p class="story__meta">
                <?php if ($cats) { ?><span class="story__cat"><?php echo html_encode($cats[0]); ?></span> · <?php } ?>
                <time><?php echo html_encode($date); ?></time>
            </p>
            <h3 class="story__title"><a href="<?php echo html_encode($obj->getLink()); ?>"><?php echo html_encode($obj->getTitle()); ?></a></h3>
            <p class="story__excerpt"><?php echo html_encode(atelier_excerpt($content, $isLarge ? 260 : 120)); ?></p>
            <?php if ($isLarge) { ?>
                <a class="story__more" href="<?php echo html_encode($obj->getLink()); ?>"><?php echo gettext('Read the story'); ?> →</a>
            <?php } ?>
        </div>
    </article>
    <?php
}

/** Titlelink of the references category from the options, or ''. */
function atelier_refCategory() {
    return trim((string) getOption('atelier_ref_category'));
}

function atelier_isRefCategory() {
    global $_CMS_current_category;
    $t = atelier_refCategory();
    return $t !== '' && is_object($_CMS_current_category) && $_CMS_current_category->getTitlelink() === $t;
}

/** One reference card: small photo (first image of the text), names (title), quote (text). */
function atelier_printRefCard($obj) {
    $content = $obj->getContent();
    $img = atelier_firstImage($content);
    $quote = $img ? atelier_withoutFirstImage($content) : $content;
    if (!$img) {
        // the photo can also be placed in the "extra content" of the article
        $img = atelier_firstImage($obj->getExtraContent());
    }
    ?>
    <figure class="ref">
        <?php if ($img) { ?>
            <img class="ref__photo" loading="lazy" decoding="async" src="<?php echo html_encode($img[0]); ?>" alt="<?php echo html_encode($img[1] !== '' ? $img[1] : $obj->getTitle()); ?>">
        <?php } ?>
        <blockquote class="ref__quote"><?php echo $quote; ?></blockquote>
        <figcaption class="ref__name"><?php echo html_encode($obj->getTitle()); ?></figcaption>
    </figure>
    <?php
}

function atelier_printHomeReferences() {
    $cat = atelier_refCategory();
    if ($cat === '' || !atelier_option('atelier_home_refs', true) || !class_exists('CMS')) {
        return;
    }
    $items = getLatestNews(4, $cat, false);
    if (!$items) {
        return;
    }
    $catobj = newCategory($cat);
    ?>
    <section class="home-section home-refs">
        <div class="section-head">
            <h2 class="section-head__title"><?php echo gettext('What clients say'); ?></h2>
            <a class="section-head__link" href="<?php echo html_encode($catobj->getLink()); ?>"><?php echo gettext('All references'); ?> →</a>
        </div>
        <div class="ref-grid">
            <?php
            foreach ($items as $item) {
                atelier_printRefCard(newArticle($item['titlelink']));
            }
            ?>
        </div>
    </section>
    <?php
}

function atelier_printHomeStories() {
    global $_zenpage_news_enabled;
    if (!$_zenpage_news_enabled) {
        return;
    }
    $opt = getOption('atelier_home_stories');
    $n = ($opt === NULL || $opt === '') ? 3 : max(0, min(5, (int) $opt));
    if ($n === 0) {
        return; // 0 = the section is switched off
    }
    $ref = atelier_refCategory();
    // latest articles without the references
    $all = getLatestNews($n + 6, '', true);
    $items = array();
    foreach ($all as $row) {
        $obj = newArticle($row['titlelink']);
        if ($ref !== '') {
            $skip = false;
            foreach ($obj->getCategories() as $c) {
                if ($c['titlelink'] === $ref) {
                    $skip = true;
                    break;
                }
            }
            if ($skip) {
                continue;
            }
        }
        $items[] = $obj;
        if (count($items) >= $n) {
            break;
        }
    }
    if (!$items) {
        return;
    }
    ?>
    <section class="home-section home-stories">
        <div class="section-head">
            <h2 class="section-head__title"><?php echo gettext('From the blog'); ?></h2>
            <a class="section-head__link" href="<?php echo html_encode(getNewsIndexURL()); ?>"><?php echo gettext('All stories'); ?> →</a>
        </div>
        <div class="story-grid">
            <?php
            $first = array_shift($items);
            atelier_printStoryCard($first, 'large');
            ?>
            <div class="story-grid__side">
                <?php foreach ($items as $obj) { atelier_printStoryCard($obj, 'small'); } ?>
            </div>
        </div>
    </section>
    <?php
}

/** Albums for the home page: folders from the options, otherwise the first visible top level albums. */
function atelier_homeAlbums($count = 4) {
    global $_gallery;
    $folders = array_filter(array_map('trim', explode(',', (string) getOption('atelier_home_albums'))));
    if (!$folders) {
        $folders = $_gallery->getAlbums(0);
    }
    $out = array();
    foreach ($folders as $folder) {
        $a = newAlbum($folder, true, true);
        if (!$a || !$a->exists || !$a->checkAccess() || !$a->getShow() && !npg_loggedin()) {
            continue;
        }
        $out[] = $a;
        if (count($out) >= $count) {
            break;
        }
    }
    return $out;
}

/* ==================================================================
 * Password protected albums: blurred preview instead of the lock image
 * ================================================================== */

/** TRUE when the album is password protected and the visitor has not unlocked it (the core would show the lock image). */
function atelier_albumLocked($album) {
    $pwd = $album->getPassword();
    return !empty($pwd) && getOption('use_lock_image') && !$album->isMyItem(LIST_RIGHTS) && !$album->checkforGuest();
}

/**
 * A tiny (24 px) JPEG of the album thumbnail as a data: URI, cached on disk.
 * The visitor never gets the address of the real thumbnail or any detailed pixels - only a few
 * colour blocks that the browser smooths with a CSS blur. '' when it cannot be made.
 */
function atelier_blurLevel() {
    // source width of the tiny image, CSS blur radius (px): the lighter the blur, the more of the image is kept
    $levels = array('light' => array(48, 6), 'medium' => array(32, 10), 'strong' => array(24, 16));
    $l = (string) getOption('atelier_blur_amount');
    return isset($levels[$l]) ? $levels[$l] : $levels['medium'];
}

function atelier_blurData($album) {
    list($tw, $blurPx) = atelier_blurLevel();
    $thumb = $album->getAlbumThumbImage();
    if (!$thumb || empty($thumb->localpath) || !is_file($thumb->localpath)) {
        return '';
    }
    $src = $thumb->localpath;
    $dir = SERVERPATH . '/' . CACHEFOLDER . '/atelier_blur/';
    $file = $dir . md5($src . '|' . filemtime($src) . '|' . $tw) . '.txt';
    if (is_file($file)) {
        return (string) @file_get_contents($file);
    }
    $jpeg = '';
    try {
        if (class_exists('Imagick')) {
            $im = new Imagick();
            $im->setOption('jpeg:size', '200x200');
            $im->readImage($src . '[0]');
            $im->thumbnailImage($tw, (int) round($tw * 1.25), true);
            $im->setImageFormat('jpeg');
            $im->setImageCompressionQuality(55);
            $jpeg = $im->getImageBlob();
            $im->clear();
        } elseif (function_exists('imagecreatefromstring')) {
            $dims = @getimagesize($src);
            $limit = (int) ini_get('memory_limit');
            $limit = ($limit > 0) ? $limit * 1048576 : 0; // memory_limit in MB (typical values 128M ...)
            if ($dims && ($limit === 0 || $dims[0] * $dims[1] * 5 < $limit * 0.5)) {
                $big = @imagecreatefromstring(file_get_contents($src));
                if ($big) {
                    $w = imagesx($big);
                    $h = imagesy($big);
                    $th = max(1, (int) round($h * $tw / $w));
                    $small = imagecreatetruecolor($tw, $th);
                    imagecopyresampled($small, $big, 0, 0, 0, 0, $tw, $th, $w, $h);
                    ob_start();
                    imagejpeg($small, null, 55);
                    $jpeg = ob_get_clean();
                }
            }
        }
    } catch (Throwable $e) {
        $jpeg = '';
    }
    if ($jpeg === '') {
        return '';
    }
    $uri = 'data:image/jpeg;base64,' . base64_encode($jpeg);
    if (is_dir($dir) || @mkdir($dir, 0755, true)) {
        @file_put_contents($file, $uri);
    }
    return $uri;
}

/** Image of a locked album tile: blurred hint (option) with a lock badge, otherwise the core lock image. */
function atelier_printLockedThumb($album, $alt = '') {
    $uri = atelier_option('atelier_blur_locked', false) ? atelier_blurData($album) : '';
    if ($uri !== '') {
        echo '<img class="tile__image tile__image--locked" style="--blur:' . atelier_blurLevel()[1] . 'px" src="' . html_encode($uri) . '" alt="' . html_encode($alt) . '">' .
        '<span class="tile__lock" aria-hidden="true">' . atelier_icon('lock', 22) . '</span>';
    } else {
        echo getPasswordProtectImage('class="tile__image" ');
    }
}

function atelier_printHomePortfolio() {
    if (!atelier_option('atelier_home_portfolio', true)) {
        return;
    }
    $albums = atelier_homeAlbums(4);
    if (!$albums) {
        return;
    }
    ?>
    <section class="home-section home-portfolio">
        <div class="section-head">
            <h2 class="section-head__title"><?php echo gettext('Portfolio'); ?></h2>
            <a class="section-head__link" href="<?php echo html_encode(getCustomPageURL('gallery')); ?>"><?php echo gettext('All albums'); ?> →</a>
        </div>
        <div class="tile-grid">
            <?php
            foreach ($albums as $a) {
                $thumb = $a->getAlbumThumbImage();
                ?>
                <a class="tile" href="<?php echo html_encode($a->getLink()); ?>">
                    <span class="tile__media">
                        <?php if (atelier_albumLocked($a)) { atelier_printLockedThumb($a); } elseif ($thumb) { ?>
                            <img loading="lazy" decoding="async" src="<?php echo html_encode($thumb->getCustomImage(array('width' => 640, 'height' => 800, 'cw' => 640, 'ch' => 800, 'thumb' => true))); ?>" alt="">
                        <?php } ?>
                    </span>
                    <span class="tile__title"><?php echo html_encode($a->getTitle()); ?></span>
                    <span class="tile__count"><?php printf(ngettext('%u image', '%u images', $a->getNumImages()), $a->getNumImages()); ?></span>
                </a>
            <?php } ?>
        </div>
    </section>
    <?php
}

/** Hero photo: random / latest (cached pool) or from a chosen album. */
function atelier_heroImage() {
    $src = getOption('atelier_hero_source');
    if ($src === 'album') {
        $folder = trim((string) getOption('atelier_hero_album'));
        if ($folder !== '') {
            $a = newAlbum($folder, true, true);
            if ($a && $a->exists && $a->checkAccess()) {
                $t = $a->getAlbumThumbImage();
                if ($t && $t->exists) {
                    return $t;
                }
            }
        }
    }
    $mode = ($src === 'latest') ? 'latest' : 'random';
    $ttl = ($mode === 'random') ? 6 * 3600 : 3600;
    $cache = getOption('atelier_hero_pool');
    $cache = $cache ? @unserialize($cache) : array();
    if (!is_array($cache)) {
        $cache = array();
    }
    if (!isset($cache[$mode]) || $cache[$mode]['t'] < time() - $ttl || empty($cache[$mode]['ids'])) {
        $order = ($mode === 'random') ? 'RAND()' : 'i.`id` DESC';
        // from the best candidates (big landscape photos) to anything visible: sizes may be missing in the database
        $tiers = array(
            ' AND a.`show` = 1 AND i.`width` >= i.`height` * 1.3 AND i.`width` >= 1600',
            ' AND a.`show` = 1 AND i.`width` > i.`height`',
            ' AND a.`show` = 1',
            ''
        );
        $ids = array();
        foreach ($tiers as $cond) {
            $rows = query_full_array('SELECT i.`id` FROM ' . prefix('images') . ' AS i JOIN ' . prefix('albums') . ' AS a ON a.`id` = i.`albumid`' .
                    ' WHERE i.`show` = 1' . $cond . ' ORDER BY ' . $order . ' LIMIT 24');
            foreach ((array) $rows as $r) {
                $ids[] = (int) $r['id'];
            }
            if (count($ids) >= 3) {
                break;
            }
        }
        $cache[$mode] = array('t' => time(), 'ids' => $ids);
        setOption('atelier_hero_pool', serialize($cache));
    }
    $ids = $cache[$mode]['ids'];
    if ($mode === 'random') {
        shuffle($ids);
    }
    foreach ($ids as $id) {
        $img = atelier_geoImage($id);
        if ($img) {
            return $img;
        }
    }
    // nothing usable in the cached list: forget it, the next page view builds a new one
    unset($cache[$mode]);
    setOption('atelier_hero_pool', serialize($cache));
    return false;
}

/**
 * Photos similar to the current one: shared tags (tags of a few hundred photos at most, so a generic
 * tag does not match half of the gallery), topped up with neighbours from the same album.
 */
function atelier_similarImages($limit = 8) {
    global $_current_image;
    if (!is_object($_current_image)) {
        return array();
    }
    $id = (int) $_current_image->getID();
    $T = prefix('obj_to_tag');
    $rows = query_full_array('SELECT o2.`objectid` AS id, COUNT(*) AS c FROM ' . $T . ' AS o1' .
            ' JOIN (SELECT `tagid` FROM ' . $T . " WHERE `type` = 'images' GROUP BY `tagid` HAVING COUNT(*) <= 400) AS ok ON ok.`tagid` = o1.`tagid`" .
            ' JOIN ' . $T . " AS o2 ON o2.`tagid` = o1.`tagid` AND o2.`type` = 'images' AND o2.`objectid` <> " . $id .
            " WHERE o1.`type` = 'images' AND o1.`objectid` = " . $id . ' GROUP BY o2.`objectid` ORDER BY c DESC, o2.`objectid` DESC LIMIT ' . ($limit * 3));
    $out = array();
    $seen = array($id => 1);
    foreach ((array) $rows as $r) {
        $img = atelier_geoImage((int) $r['id']);
        if ($img) {
            $out[] = $img;
            $seen[(int) $r['id']] = 1;
            if (count($out) >= $limit) {
                return $out;
            }
        }
    }
    // top up from the same album
    $rows = query_full_array('SELECT `id` FROM ' . prefix('images') . ' WHERE `albumid` = ' . (int) $_current_image->album->getID() .
            ' AND `show` = 1 AND `id` <> ' . $id . ' ORDER BY `id` DESC LIMIT 40');
    foreach ((array) $rows as $r) {
        if (isset($seen[(int) $r['id']])) {
            continue;
        }
        $img = atelier_geoImage((int) $r['id']);
        if ($img) {
            $out[] = $img;
            if (count($out) >= $limit) {
                break;
            }
        }
    }
    return $out;
}

function atelier_printSimilar() {
    $items = atelier_similarImages(8);
    if (count($items) < 2) {
        return;
    }
    ?>
    <section class="home-section similar">
        <div class="section-head"><h2 class="section-head__title"><?php echo gettext('Similar images'); ?></h2></div>
        <div class="similar__grid">
            <?php foreach ($items as $img) { ?>
                <a class="similar__item" href="<?php echo html_encode($img->getLink()); ?>" title="<?php echo html_encode($img->getTitle()); ?>">
                    <img loading="lazy" decoding="async" src="<?php echo html_encode($img->getCustomImage(array('width' => 420, 'height' => 420, 'cw' => 420, 'ch' => 420, 'thumb' => true))); ?>" alt="<?php echo html_encode($img->getTitle()); ?>">
                </a>
            <?php } ?>
        </div>
    </section>
    <?php
}

/** Map of the current photo (own small Leaflet map, initialised in atelier.js). */
function atelier_printImageMap() {
    global $_current_image;
    if (!is_object($_current_image) || !atelier_option('zpB_show_map', true)) {
        return false;
    }
    $lat = $_current_image->getGPSLatitude();
    $lon = $_current_image->getGPSLongitude();
    if (empty($lat) || empty($lon) || abs($lat) > 90 || abs($lon) > 180) {
        return false;
    }
    echo '<section class="side-block"><h2 class="side-block__title">' . atelier_icon('map') . ' ' . html_encode(gettext('Where it was taken')) . '</h2>' .
    '<div class="photo-map" id="atelier-photomap" data-lat="' . html_encode((string) $lat) . '" data-lon="' . html_encode((string) $lon) . '"' .
    ' data-attribution="' . html_encode('&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>') . '"></div></section>';
    return true;
}

/** Share / social meta (Open Graph + Twitter card) for blog posts, pages, albums and photos. */
function atelier_printOpenGraph() {
    global $_gallery_page, $_current_image, $_current_album, $_CMS_current_article, $_CMS_current_page;
    $title = $desc = $image = '';
    $type = 'website';
    $url = '';
    switch ($_gallery_page) {
        case 'news.php':
            if (is_NewsArticle() && is_object($_CMS_current_article)) {
                $type = 'article';
                $title = $_CMS_current_article->getTitle();
                $content = $_CMS_current_article->getContent();
                $desc = atelier_excerpt($content, 200);
                $i = atelier_firstImage($content);
                $image = $i ? $i[0] : '';
                $url = $_CMS_current_article->getLink();
            }
            break;
        case 'pages.php':
            if (is_object($_CMS_current_page)) {
                $title = $_CMS_current_page->getTitle();
                $content = $_CMS_current_page->getContent();
                $desc = atelier_excerpt($content, 200);
                $i = atelier_firstImage($content);
                $image = $i ? $i[0] : '';
                $url = $_CMS_current_page->getLink();
            }
            break;
        case 'image.php':
            if (is_object($_current_image)) {
                $type = 'article';
                $title = $_current_image->getTitle();
                $desc = atelier_excerpt($_current_image->getDesc(), 200);
                $image = $_current_image->getCustomImage(array('width' => 1200, 'height' => 630, 'cw' => 1200, 'ch' => 630, 'thumb' => true));
                $url = $_current_image->getLink();
            }
            break;
        case 'album.php':
            if (is_object($_current_album)) {
                $title = $_current_album->getTitle();
                $desc = atelier_excerpt($_current_album->getDesc(), 200);
                $t = $_current_album->getAlbumThumbImage();
                if ($t) {
                    $image = $t->getCustomImage(array('width' => 1200, 'height' => 630, 'cw' => 1200, 'ch' => 630, 'thumb' => true));
                }
                $url = $_current_album->getLink();
            }
            break;
    }
    if ($title === '') {
        return;
    }
    if ($desc === '') {
        $desc = atelier_excerpt(getGalleryDesc(), 200);
    }
    if ($image !== '' && !preg_match('~^https?:~i', $image)) {
        $image = FULLHOSTPATH . '/' . ltrim($image, '/');
    }
    $tags = array('og:site_name' => atelier_siteName(), 'og:type' => $type, 'og:title' => $title, 'og:description' => $desc, 'og:url' => $url, 'og:image' => $image);
    foreach ($tags as $k => $v) {
        if ($v !== '') {
            echo '<meta property="' . $k . '" content="' . html_encode($v) . '">' . "\n";
        }
    }
    echo '<meta name="twitter:card" content="' . ($image !== '' ? 'summary_large_image' : 'summary') . '">' . "\n";
    if ($desc !== '') {
        echo '<meta name="description" content="' . html_encode($desc) . '">' . "\n";
    }
}

/** Site name: the gallery name from the options, else the gallery title, else the host name. */
function atelier_siteName() {
    $n = trim((string) getMainSiteName());
    if ($n === '') {
        $n = trim(strip_tags((string) getBareGalleryTitle()));
    }
    if ($n === '') {
        $n = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'Atelier';
    }
    return $n;
}
