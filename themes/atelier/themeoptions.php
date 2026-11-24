<?php

/* Theme options for Atelier */

require_once(SERVERPATH . '/' . CORE_FOLDER . '/admin-functions.php');

class ThemeOptions {

    function __construct() {

        $me = basename(__DIR__);
        setThemeOptionDefault('albums_per_page', 6);
        setThemeOptionDefault('images_per_row', 4);
        setThemeOptionDefault('images_per_page', 24);
        setThemeOptionDefault('thumb_size', 640);
        setThemeOptionDefault('thumb_crop', 0);
        purgeOption('image_size', $me);
        setThemeOptionDefault('image_size', 1800);
        setThemeOptionDefault('image_use_side', 'longest');
        setThemeOptionDefault('custom_index_page', 'gallery');

        // colours
        setThemeOptionDefault('atelier_scheme', 'bila');
        setThemeOptionDefault('atelier_custom_accent', '#1b5d8f');
        setThemeOptionDefault('atelier_mode', 'auto');
        setThemeOptionDefault('atelier_toggle', true);

        // home page
        setThemeOptionDefault('zpB_homepage', true);
        setThemeOptionDefault('atelier_hero_source', 'random');
        setThemeOptionDefault('atelier_hero_album', '');
        setThemeOptionDefault('atelier_hero_title', '');
        setThemeOptionDefault('atelier_hero_text', '');
        setThemeOptionDefault('atelier_hero_button', '');
        setThemeOptionDefault('atelier_home_stories', 3);
        setThemeOptionDefault('atelier_home_portfolio', true);
        setThemeOptionDefault('atelier_blur_locked', false);
        setThemeOptionDefault('atelier_blur_amount', 'medium');
        setThemeOptionDefault('atelier_home_albums', '');
        setThemeOptionDefault('atelier_about_page', '');
        setThemeOptionDefault('atelier_ref_category', '');
        setThemeOptionDefault('atelier_home_refs', true);
        setThemeOptionDefault('zpB_home_stats', false);

        // login page
        setThemeOptionDefault('atelier_login_text', '');
        setThemeOptionDefault('atelier_login_link_text', '');
        setThemeOptionDefault('atelier_login_link_url', '');
        setThemeOptionDefault('atelier_login_user', false);

        // other
        setThemeOptionDefault('zpB_allow_search', true);
        setThemeOptionDefault('zpB_exerpt_length', 200);
        setThemeOptionDefault('zpB_show_map', true);
        setThemeOptionDefault('zpB_show_map_page', true);
        setThemeOptionDefault('zpB_show_tags', true);
        setThemeOptionDefault('zpB_show_exif', true);
        setThemeOptionDefault('atelier_album_filter', true);
        setThemeOptionDefault('atelier_similar', true);
        setThemeOptionDefault('zpB_show_stats', false);
        setThemeOptionDefault('zpB_custom_menu', false);

        if (class_exists('cacheManager')) {
            cacheManager::deleteCacheSizes($me);
        }

        if (class_exists('menu_manager')) {
            $menuitems = array(
                array('type' => 'siteindex', 'title' => gettext('Home'), 'link' => '', 'show' => 1, 'nesting' => 0),
                array('type' => 'albumindex', 'title' => gettext('Portfolio'), 'link' => '', 'show' => 1, 'nesting' => 0),
                array('type' => 'newsindex', 'title' => NEWS_LABEL, 'link' => '', 'show' => 1, 'nesting' => 0),
                array('type' => 'menufunction', 'title' => gettext('Pages'), 'link' => 'printPageMenu("list-top", "", "active", "", "", "", 0, false);', 'show' => 1, 'nesting' => 0),
            );
            createMenuIfNotExists($menuitems, 'atelier');
        }
    }

    function getOptionsDisabled() {
        return array('thumb_size', 'image_size', 'custom_index_page', 'thumb_crop');
    }

    function getOptionsSupported() {
        $schemes = function_exists('atelier_schemes') ? atelier_schemes() : array(
    'terakota' => gettext('Terracotta'), 'les' => gettext('Forest'), 'ocean' => gettext('Ocean'),
    'svestka' => gettext('Plum'), 'pisek' => gettext('Sand'), 'grafit' => gettext('Graphite'), 'bila' => gettext('White'));
        $selections = array();
        foreach ($schemes as $k => $label) {
            $selections[$label] = $k;
        }
        $selections[gettext('Custom accent colour')] = 'custom';

        return array(
            gettext('Colour choice') => array('order' => 0, 'key' => 'atelier_swatches', 'type' => OPTION_TYPE_CUSTOM,
                'desc' => gettext('Click a square to select the colour scheme. The square shows the background and the accent colour (light variant; the dark variant is in the lower right corner). All text and button colours meet the WCAG AA contrast.')),
            gettext('Colour scheme (technical)') => array('order' => 0.01, 'key' => 'atelier_scheme', 'type' => OPTION_TYPE_SELECTOR,
                'selections' => $selections,
                'desc' => gettext('Every scheme has a light and a dark variant. All text and button colours meet the WCAG AA contrast.')),
            gettext('Custom accent colour') => array('order' => 0.1, 'key' => 'atelier_custom_accent', 'type' => OPTION_TYPE_COLOR_PICKER,
                'desc' => gettext('Used when the scheme "Custom accent colour" is selected.')),
            gettext('Contrast check') => array('order' => 0.2, 'key' => 'atelier_contrast', 'type' => OPTION_TYPE_CUSTOM,
                'desc' => gettext('A colour that would be hard to read is not rejected: the nearest colour with a sufficient contrast is used instead (and a lighter variant for the dark mode).')),
            gettext('Light / dark mode') => array('order' => 0.3, 'key' => 'atelier_mode', 'type' => OPTION_TYPE_SELECTOR,
                'selections' => array(gettext('According to the device') => 'auto', gettext('Always light') => 'light', gettext('Always dark') => 'dark'),
                'desc' => gettext('The default for visitors who have not chosen yet.')),
            gettext('Light / dark toggle in the menu') => array('order' => 0.4, 'key' => 'atelier_toggle', 'type' => OPTION_TYPE_CHECKBOX,
                'desc' => gettext('Visitors can switch between the light and dark variant (they never choose the colours). Without the toggle everybody gets the default above.')),

            gettext('Home page: hero image') => array('order' => 1, 'key' => 'atelier_hero_source', 'type' => OPTION_TYPE_SELECTOR,
                'selections' => array(gettext('Random landscape image') => 'random', gettext('Latest landscape image') => 'latest', gettext('Thumbnail of an album') => 'album'),
                'desc' => gettext('The big image at the top. Random and latest are chosen from a cached list (random: 6 hours, latest: 1 hour), so the page stays fast.')),
            gettext('Hero album') => array('order' => 1.1, 'key' => 'atelier_hero_album', 'type' => OPTION_TYPE_TEXTBOX,
                'desc' => gettext('Folder name of the album (e.g. weddings/2025) - used with "Thumbnail of an album".')),
            gettext('Hero headline') => array('order' => 1.2, 'key' => 'atelier_hero_title', 'type' => OPTION_TYPE_TEXTBOX,
                'desc' => gettext('Empty = the gallery title.')),
            gettext('Hero text') => array('order' => 1.3, 'key' => 'atelier_hero_text', 'type' => OPTION_TYPE_TEXTBOX,
                'desc' => gettext('One sentence below the headline; it is also shown in the footer under the site name. Empty = nothing.')),
            gettext('Hero button text') => array('order' => 1.4, 'key' => 'atelier_hero_button', 'type' => OPTION_TYPE_TEXTBOX,
                'desc' => gettext('Empty = "See the portfolio". The button leads to the album list.')),
            gettext('Stories on the home page') => array('order' => 1.5, 'key' => 'atelier_home_stories', 'type' => OPTION_TYPE_NUMBER,
                'desc' => gettext('0 to 5 latest articles (one big, the others small). 0 = hide the section. Articles of the references category are not included.')),
            gettext('Portfolio on the home page') => array('order' => 1.55, 'key' => 'atelier_home_portfolio', 'type' => OPTION_TYPE_CHECKBOX,
                'desc' => gettext('Show the Portfolio section (album tiles) on the home page. Untick to hide it.')),
            gettext('Blurred preview of protected albums') => array('order' => 1.58, 'key' => 'atelier_blur_locked', 'type' => OPTION_TYPE_CHECKBOX,
                'desc' => gettext('Albums with a password show a blurred version of their cover image with a lock instead of the plain lock picture. Only a tiny 24 px image is sent to visitors (a few colour blocks, no detail). Needs the nPG option "lock image for protected albums" to be on.')),
            gettext('Blur strength') => array('order' => 1.59, 'key' => 'atelier_blur_amount', 'type' => OPTION_TYPE_SELECTOR,
                'selections' => array(gettext('Light blur (a hint of the image)') => 'light', gettext('Medium blur') => 'medium', gettext('Strong blur (colours only)') => 'strong'),
                'desc' => gettext('The lighter the blur, the more of the cover photo can be recognised. Keep it strong for private client albums.')),
            gettext('Albums on the home page') => array('order' => 1.6, 'key' => 'atelier_home_albums', 'type' => OPTION_TYPE_TEXTBOX,
                'desc' => gettext('Up to 4 album folders separated by commas. Empty = the first albums of the gallery.')),
            gettext('"About me" page') => array('order' => 1.7, 'key' => 'atelier_about_page', 'type' => OPTION_TYPE_TEXTBOX,
                'desc' => gettext('Titlelink of a Zenpage page (the address of the page without the domain), shown as the "About me" block on the home page. Empty = no block.')),
            gettext('References category') => array('order' => 1.8, 'key' => 'atelier_ref_category', 'type' => OPTION_TYPE_TEXTBOX,
                'desc' => gettext('Titlelink of the news category with references. One article = one reference: the title is the name(s), the first image is the small image, the text is the quote. Empty = no references.')),
            gettext('References on the home page') => array('order' => 1.9, 'key' => 'atelier_home_refs', 'type' => OPTION_TYPE_CHECKBOX,
                'desc' => gettext('Show a strip with the latest four references on the home page.')),
            gettext('Statistics and tag cloud on the home page') => array('order' => 2, 'key' => 'zpB_home_stats', 'type' => OPTION_TYPE_CHECKBOX,
                'desc' => gettext('Numbers of images, albums, pages and news and a cloud of the most used tags at the bottom of the home page (cached for 6 hours).')),

            gettext('Login page: welcome text') => array('order' => 3, 'key' => 'atelier_login_text', 'type' => OPTION_TYPE_TEXTBOX,
                'desc' => gettext('Empty = "Enter the password you received from the photographer."')),
            gettext('Login page: help link text') => array('order' => 3.1, 'key' => 'atelier_login_link_text', 'type' => OPTION_TYPE_TEXTBOX,
                'desc' => gettext('Empty = "No access? Write to me".')),
            gettext('Login page: help link address') => array('order' => 3.2, 'key' => 'atelier_login_link_url', 'type' => OPTION_TYPE_TEXTBOX,
                'desc' => gettext('Empty = the contact page (when the contact form is enabled).')),

            gettext('Album password page: ask for a user name') => array('order' => 3.3, 'key' => 'atelier_login_user', 'type' => OPTION_TYPE_CHECKBOX,
                'desc' => gettext('Off = password only (clients get just a password). On = user name and password. The login window opened from the menu always asks for both.')),

            gettext('Allow search') => array('order' => 5, 'key' => 'zpB_allow_search', 'type' => OPTION_TYPE_CHECKBOX,
                'desc' => gettext('Show the search icon in the menu.')),
            gettext('Excerpt length') => array('order' => 6, 'key' => 'zpB_exerpt_length', 'type' => OPTION_TYPE_NUMBER,
                'desc' => gettext('Excerpt length for news and pages lists in search page.')),
            gettext('Tags') => array('order' => 8, 'key' => 'zpB_show_tags', 'type' => OPTION_TYPE_CHECKBOX,
                'desc' => gettext('Show tags on the image page and a tag cloud in the Archive.')),
            gettext('Exif') => array('order' => 9, 'key' => 'zpB_show_exif', 'type' => OPTION_TYPE_CHECKBOX,
                'desc' => gettext('Show the shooting data on the image page. The metadata to show is chosen in Options > Image > Metadata.')),
            gettext('Map') => array('order' => 10, 'key' => 'zpB_show_map', 'type' => OPTION_TYPE_CHECKBOX,
                'desc' => gettext('Show a map on album pages and on the image page when the images have GPS coordinates (needs the openStreetMap plugin).')),
            gettext('Image map page') => array('order' => 11, 'key' => 'zpB_show_map_page', 'type' => OPTION_TYPE_CHECKBOX,
                'desc' => gettext('Enable the "Image map" page (/page/photomap) with all images that have GPS coordinates, plus its menu link. Safe for very large galleries: only the visible part of the map is loaded and nearby images are grouped on the server.')),
            gettext('Filter chips in albums') => array('order' => 12, 'key' => 'atelier_album_filter', 'type' => OPTION_TYPE_CHECKBOX,
                'desc' => gettext('Chips with the tags of the images on the page that filter the album without reloading. Uses one extra database query per image; disable it for albums with very many images per page.')),
            gettext('Similar images') => array('order' => 13, 'key' => 'atelier_similar', 'type' => OPTION_TYPE_CHECKBOX,
                'desc' => gettext('Show similar images (shared tags, otherwise the same album) below the image.')),
            gettext('Use custom menu') => array('order' => 14, 'key' => 'zpB_custom_menu', 'type' => OPTION_TYPE_CHECKBOX,
                'desc' => gettext('Use the "menu_manager" menu named "atelier" instead of the standard menu.')),
            gettext('Footer statistics') => array('order' => 15, 'key' => 'zpB_show_stats', 'type' => OPTION_TYPE_CHECKBOX,
                'desc' => gettext('Show GPS and description statistics in the footer (a few database counts on every page; disable on very large galleries).')),
        );
    }

    /**
     * Live contrast check for the custom accent colour (same algorithm as atelier_customColors() in PHP).
     */
    function handleOption($option, $currentValue) {
        if ($option === 'atelier_swatches') {
            $this->printSwatches();
            return;
        }
        if ($option !== 'atelier_contrast') {
            return;
        }
        $msg = array(
            'ok' => gettext('The colour is readable on light and dark backgrounds.'),
            'adj' => gettext('The colour is too light or too dark for small text. Used instead:'),
            'light' => gettext('Light'),
            'dark' => gettext('Dark'),
        );
        ?>
        <div id="atelier-contrast" style="display:grid;gap:.5rem;max-width:34rem">
            <div id="atelier-contrast-msg"></div>
            <div style="display:flex;gap:1rem;flex-wrap:wrap">
                <div id="atelier-sw-light" style="padding:.6rem .9rem;border:1px solid #bbb;background:#f6f5f2;border-radius:6px;min-width:10rem"></div>
                <div id="atelier-sw-dark" style="padding:.6rem .9rem;border:1px solid #444;background:#141413;border-radius:6px;min-width:10rem"></div>
            </div>
        </div>
        <script>
            (function () {
                var T =<?php echo json_encode($msg); ?>;
                function rgb(h) {
                    return [0, 2, 4].map(function (i) {
                        return parseInt(h.substr(i, 2), 16) / 255;
                    });
                }
                function lum(h) {
                    var c = rgb(h).map(function (v) {
                        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
                    });
                    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
                }
                function cr(a, b) {
                    var x = lum(a), y = lum(b);
                    if (x < y) {
                        var t = x;
                        x = y;
                        y = t;
                    }
                    return (x + 0.05) / (y + 0.05);
                }
                function toHsl(c) {
                    var r = c[0], g = c[1], b = c[2], mx = Math.max(r, g, b), mn = Math.min(r, g, b), l = (mx + mn) / 2, h = 0, s = 0, d = mx - mn;
                    if (d) {
                        s = l > 0.5 ? d / (2 - mx - mn) : d / (mx + mn);
                        h = mx === r ? (g - b) / d + (g < b ? 6 : 0) : mx === g ? (b - r) / d + 2 : (r - g) / d + 4;
                        h /= 6;
                    }
                    return [h, s, l];
                }
                function toHex(h, s, l) {
                    function f(p, q, t) {
                        if (t < 0)
                            t += 1;
                        if (t > 1)
                            t -= 1;
                        if (t < 1 / 6)
                            return p + (q - p) * 6 * t;
                        if (t < 1 / 2)
                            return q;
                        if (t < 2 / 3)
                            return p + (q - p) * (2 / 3 - t) * 6;
                        return p;
                    }
                    var r, g, b;
                    if (!s) {
                        r = g = b = l;
                    } else {
                        var q = l < 0.5 ? l * (1 + s) : l + s - l * s, p = 2 * l - q;
                        r = f(p, q, h + 1 / 3);
                        g = f(p, q, h);
                        b = f(p, q, h - 1 / 3);
                    }
                    return [r, g, b].map(function (v) {
                        return ('0' + Math.round(v * 255).toString(16)).slice(-2);
                    }).join('');
                }
                function fit(hex, bgs, dir) {
                    function ok(c) {
                        return bgs.every(function (b) {
                            return cr(c, b) >= 4.5;
                        });
                    }
                    if (ok(hex))
                        return hex;
                    var hsl = toHsl(rgb(hex));
                    for (var i = 0; i < 100; i++) {
                        hsl[2] = Math.max(0, Math.min(1, hsl[2] + dir * 0.01));
                        var c = toHex(hsl[0], hsl[1], hsl[2]);
                        if (ok(c))
                            return c;
                    }
                    return dir < 0 ? '000000' : 'ffffff';
                }
                function sw(el, label, hex, bg) {
                    el.innerHTML = '<strong style="color:#' + hex + '">' + label + ' – Aa</strong><br><small style="color:#' + (bg === '141413' ? 'ccc' : '444') + '">#' + hex + ' · ' + cr(hex, bg).toFixed(1) + ':1</small>';
                }
                function update() {
                    var inp = document.getElementById('__atelier_custom_accent');
                    if (!inp)
                        return;
                    var v = (inp.value || '').replace('#', '').trim().toLowerCase();
                    if (v.length === 3)
                        v = v.replace(/(.)/g, '$1$1');
                    if (!/^[0-9a-f]{6}$/.test(v))
                        return;
                    var l = fit(v, ['f6f5f2', 'ffffff', 'eeede9'], -1), d = fit(v, ['141413', '1d1d1b', '262624'], +1);
                    document.getElementById('atelier-contrast-msg').textContent = (l === v) ? T.ok : T.adj;
                    sw(document.getElementById('atelier-sw-light'), T.light, l, 'f6f5f2');
                    sw(document.getElementById('atelier-sw-dark'), T.dark, d, '141413');
                }
                window.addEventListener('load', function () {
                    var inp = document.getElementById('__atelier_custom_accent');
                    if (inp) {
                        ['input', 'change', 'keyup'].forEach(function (e) {
                            inp.addEventListener(e, update);
                        });
                        if (window.jQuery) {
                            jQuery(inp).on('change move.spectrum hide.spectrum dragstop.spectrum', update);
                        }
                        setInterval(update, 600);
                    }
                    update();
                });
            })();
        </script>
        <?php
    }


    /** Squares with the colours of every scheme (read from css/schemes.css); a click selects the scheme. */
    private function printSwatches() {
        $css = @file_get_contents(__DIR__ . '/css/schemes.css');
        $colors = array();
        if ($css && preg_match_all('~data-scheme="([a-z]+)"\]\[data-theme="(light|dark)"\]\s*\{[^}]*?--bg:(#[0-9a-f]{6});[^}]*?--accent:(#[0-9a-f]{6});~s', $css, $m, PREG_SET_ORDER)) {
            foreach ($m as $r) {
                $colors[$r[1]][$r[2]] = array($r[3], $r[4]);
            }
        }
        $labels = array(
            'terakota' => gettext('Terracotta'), 'les' => gettext('Forest'), 'ocean' => gettext('Ocean'),
            'svestka' => gettext('Plum'), 'pisek' => gettext('Sand'), 'grafit' => gettext('Graphite'), 'bila' => gettext('White'),
            'custom' => gettext('Custom accent colour'));
        // the custom scheme: the raw colour (the page updates it while the colour is being picked)
        $raw = preg_match('/^#[0-9a-fA-F]{6}$/', (string) getOption('atelier_custom_accent')) ? getOption('atelier_custom_accent') : '#1b5d8f';
        $colors['custom'] = array('light' => array('#f6f5f2', $raw), 'dark' => array('#141413', $raw));
        $current = getOption('atelier_scheme');
        ?>
        <div id="atelier-swatches" style="display:flex;flex-wrap:wrap;gap:.6rem">
            <?php
            foreach ($labels as $k => $label) {
                if (!isset($colors[$k])) {
                    continue;
                }
                $l = $colors[$k]['light'];
                $d = $colors[$k]['dark'];
                ?>
                <button type="button" class="atelier-swatch" data-scheme="<?php echo html_encode($k); ?>" title="<?php echo html_encode($label); ?>"
                        style="all:unset;cursor:pointer;display:flex;flex-direction:column;align-items:center;gap:.25rem;padding:.3rem;border-radius:8px;border:2px solid <?php echo $k === $current ? '#555' : 'transparent'; ?>">
                    <span style="position:relative;display:block;width:56px;height:56px;border-radius:6px;border:1px solid #999;overflow:hidden;background:<?php echo $l[0]; ?>">
                        <span data-accent style="position:absolute;left:10px;top:10px;width:36px;height:36px;border-radius:50%;background:<?php echo $l[1]; ?>"></span>
                        <span style="position:absolute;right:0;bottom:0;width:22px;height:22px;background:<?php echo $d[0]; ?>;border-top-left-radius:6px">
                            <span data-accent style="position:absolute;left:5px;top:5px;width:12px;height:12px;border-radius:50%;background:<?php echo $d[1]; ?>"></span>
                        </span>
                    </span>
                    <span style="font-size:11px;line-height:1.2"><?php echo html_encode($label); ?></span>
                </button>
            <?php } ?>
        </div>
        <script>
            (function () {
                var wrap = document.getElementById('atelier-swatches');
                function sel() {
                    return document.getElementById('__atelier_scheme');
                }
                function rows() {
                    var s = sel(), isCustom = s && s.value === 'custom';
                    var hide = document.getElementById('tr_ThemeOptions_atelier_scheme');
                    if (hide) {
                        hide.style.display = 'none';
                    }
                    ['tr_ThemeOptions_atelier_custom_accent', 'tr_ThemeOptions_atelier_contrast'].forEach(function (id) {
                        var r = document.getElementById(id);
                        if (r) {
                            r.style.display = isCustom ? '' : 'none';
                        }
                    });
                }
                function custom() {
                    var i = document.getElementById('__atelier_custom_accent'), v = i ? i.value : '';
                    if (/^#[0-9a-fA-F]{6}$/.test(v)) {
                        wrap.querySelectorAll('[data-scheme="custom"] [data-accent]').forEach(function (e) {
                            e.style.background = v;
                        });
                    }
                }
                function mark() {
                    var s = sel();
                    wrap.querySelectorAll('.atelier-swatch').forEach(function (b) {
                        b.style.borderColor = (s && b.getAttribute('data-scheme') === s.value) ? '#555' : 'transparent';
                    });
                }
                wrap.addEventListener('click', function (e) {
                    var b = e.target.closest('.atelier-swatch'), s = sel();
                    if (b && s) {
                        s.value = b.getAttribute('data-scheme');
                        s.dispatchEvent(new Event('change', {bubbles: true}));
                        mark();
                        rows();
                    }
                });
                window.addEventListener('load', function () {
                    var s = sel();
                    if (s) {
                        s.addEventListener('change', mark);
                    }
                    mark();
                    rows();
                    setInterval(custom, 600);
                });
            })();
        </script>
        <?php
    }

}
