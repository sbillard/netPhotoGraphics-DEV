<?php
/* Masonry of the photos on the page. Thumbnails are not cropped, so the aspect ratios are kept. */
$_atelier_filter = atelier_option('atelier_album_filter', true) && !in_array($_gallery_page, array('search.php')) && (int) getOption('images_per_page') <= 80;
$_atelier_tagset = array();
ob_start();
while (next_image()) {
    $fullimage = getFullImageURL();
    if (empty($fullimage)) {
        continue;
    }
    $isPhoto = $_current_image->isPhoto();
    $isVideo = $_current_image->isVideo();
    $isAudio = false;
    if ($isVideo) {
        $suffix = strtolower(getSuffix($_current_image->getFileName()));
        $isAudio = ($suffix == 'mp3' || $suffix == 'm4a');
    }
    $objectclass = strtolower(get_class($_current_image));
    $isTextObject = $objectclass == 'textobject';
    $isEmbedLink = $objectclass == 'externallink';

    // how does the thumbnail open?
    $attrs = 'href="' . html_encode($fullimage) . '" data-fancybox="images"';
    if ($isPhoto || ($isVideo && !$isAudio)) {
        // default
    } else if ($isVideo && $isAudio) {
        $attrs = 'href="javascript:;" data-type="iframe" data-src="' . html_encode($fullimage) . '" data-fancybox="images"';
    } else if ($isEmbedLink) {
        $attrs = 'href="' . html_encode(zpB_getLink($_current_image->getContent())) . '" data-fancybox="images"';
    } else if ($isTextObject) {
        $attrs = 'href="javascript:;" data-src="#item' . $_current_image->getIndex() . '" data-fancybox="images"';
    } else {
        $attrs = 'href="' . html_encode(getImageURL()) . '"';
    }
    if ($_gallery_page == 'search.php') {
        // search results lead to the image page, not to the full-screen lightbox
        $attrs = 'href="' . html_encode(getImageURL()) . '"';
    }
    $tagAttr = '';
    if ($_atelier_filter) {
        $tags = array_values(array_filter((array) $_current_image->getTags()));
        foreach ($tags as $tg) {
            $_atelier_tagset[$tg] = isset($_atelier_tagset[$tg]) ? $_atelier_tagset[$tg] + 1 : 1;
        }
        $tagAttr = ' data-tags="' . html_encode(json_encode($tags, JSON_UNESCAPED_UNICODE)) . '"';
    }
    ?>
    <figure class="shot"<?php echo $tagAttr; ?>>
        <a class="shot__thumb" <?php echo $attrs; ?> title="<?php echo html_encode(getBareImageTitle()); ?>">
            <?php printImageThumb(getBareImageTitle(), 'shot__image'); ?>
            <span class="caption" hidden>
                <h4><?php printBareImageTitle(); ?></h4>
                <?php printImageDesc(); ?>
            </span>
        </a>
        <?php if ($isTextObject) { ?>
            <div id="item<?php echo $_current_image->getIndex(); ?>" hidden><?php echo $_current_image->getContent(); ?></div>
        <?php } ?>
        <figcaption class="shot__title">
            <a href="<?php echo html_encode(getImageURL()); ?>" title="<?php echo html_encode(getBareImageTitle()); ?>"><?php printBareImageTitle(); ?></a>
        </figcaption>
    </figure>
    <?php
}
$_atelier_shots = ob_get_clean();

if ($_atelier_filter && count($_atelier_tagset) > 1) {
    arsort($_atelier_tagset);
    $_atelier_chips = array_slice(array_keys($_atelier_tagset), 0, 14);
    localeSort($_atelier_chips);
    ?>
    <nav class="chip-bar chip-bar--filter" aria-label="<?php echo html_encode(gettext('Filter images on this page')); ?>" data-filter-bar>
        <span class="chip-bar__label"><?php echo gettext('Filter'); ?>:</span>
        <ul class="chip-list">
            <li><button type="button" class="chip is-active" data-filter=""><?php echo gettext('All'); ?></button></li>
            <?php foreach ($_atelier_chips as $chip) { ?>
                <li><button type="button" class="chip" data-filter="<?php echo html_encode($chip); ?>"><?php echo html_encode($chip); ?> <small>(<?php echo (int) $_atelier_tagset[$chip]; ?>)</small></button></li>
            <?php } ?>
        </ul>
    </nav>
<?php } ?>
<div class="masonry"<?php echo $_atelier_filter ? ' data-filterable' : ''; ?>>
    <?php echo $_atelier_shots; ?>
</div>
