<?php
/* Photo map: all geotagged photos on one map, loaded by viewport (see atelier_geoEndpoint) */
if (!defined('WEBPATH')) {
    die();
}
if (!atelier_mapPageEnabled()) {
    include(CORE_SERVERPATH . '404.php');
    return;
}
if (isset($_GET['atelier_geo'])) {
    atelier_geoEndpoint(); // prints JSON and exits
}
$_atelier_meta = atelier_geoMeta();
include('includes/header.php');
?>
<nav class="breadcrumb">
    <?php printCustomPageURL(getGalleryTitle() ? getGalleryTitle() : gettext('Gallery'), 'gallery', '', '', ' » '); ?><?php echo gettext('Image map'); ?>
</nav>

<header class="page-header">
    <h1 class="page-title"><?php echo gettext('Image map'); ?></h1>
    <?php if ($_atelier_meta['n'] > 0) { ?>
        <p class="page-description"><?php printf(gettext('%s images with GPS coordinates. Zoom in to see single images, click a marker to open them.'), '<strong>' . number_format($_atelier_meta['n'], 0, ',', "\xC2\xA0") . '</strong>'); ?></p>
    <?php } ?>
</header>

<?php if ($_atelier_meta['n'] > 0) { ?>
    <div class="geomap-wrap">
        <div id="atelier-geomap" class="geomap"
             data-config="<?php echo html_encode(json_encode(array(
                 'endpoint' => getCustomPageURL('photomap'),
                 'bounds' => $_atelier_meta['bounds'],
                 'total' => $_atelier_meta['n'],
                 'attribution' => '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
                 'i18n' => array(
                     'loading' => gettext('Loading…'),
                     'shown' => gettext('Images in view:'),
                     'more' => gettext('and %s more – zoom in'),
                     'error' => gettext('The map data could not be loaded.'),
                 ),
             ))); ?>"></div>
        <div class="geomap-status" id="atelier-geomap-status" aria-live="polite"></div>
        <noscript><p><?php echo gettext('The map needs JavaScript.'); ?></p></noscript>
    </div>
    <script src="<?php echo html_encode($_themeroot . '/js/atelier-map.js?v=' . @filemtime(__DIR__ . '/js/atelier-map.js')); ?>"></script>
<?php } else { ?>
    <p class="panel"><?php echo gettext('There are no images with GPS coordinates.'); ?></p>
<?php } ?>

<?php include('includes/footer.php'); ?>
