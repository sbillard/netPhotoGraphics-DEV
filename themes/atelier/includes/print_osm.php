<?php if (atelier_albumHasGeodata()) { ?>
    <section class="panel osm_panel">
        <h2 class="panel__title"><?php echo atelier_icon('map'); ?> <?php echo gettext('Map'); ?></h2>
        <div class="panel__body"><?php printOpenStreetMap(); ?></div>
    </section>
<?php } ?>
