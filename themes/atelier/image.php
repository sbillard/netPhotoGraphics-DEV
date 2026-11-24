<?php include('includes/header.php'); ?>

<div class="container container--wide">
    <?php include('includes/print_breadcrumb.php'); ?>

    <div class="photo-layout">
        <div class="photo-layout__main">
            <div class="photo-stage">
                <?php printDefaultSizedImage(getBareImageTitle(), 'photo-stage__image'); ?>
            </div>
            <nav class="photo-pager" aria-label="<?php echo html_encode(gettext('Images')); ?>">
                <?php if (hasPrevImage()) { ?>
                    <a class="button" rel="prev" href="<?php echo html_encode(getPrevImageURL()); ?>" title="<?php echo html_encode(gettext('Previous Image')); ?>">← <?php echo gettext('prev'); ?></a>
                <?php } else { ?>
                    <span class="button is-disabled">← <?php echo gettext('prev'); ?></span>
                <?php } ?>
                <span class="photo-pager__pos"><?php echo imageNumber(); ?> / <?php echo getNumImages(); ?></span>
                <?php if (hasNextImage()) { ?>
                    <a class="button" rel="next" href="<?php echo html_encode(getNextImageURL()); ?>" title="<?php echo html_encode(gettext('Next Image')); ?>"><?php echo gettext('next'); ?> →</a>
                <?php } else { ?>
                    <span class="button is-disabled"><?php echo gettext('next'); ?> →</span>
                <?php } ?>
            </nav>
        </div>

        <aside class="photo-layout__side">
            <h1 class="photo-title"><?php printBareImageTitle(); ?></h1>
            <?php if (trim(strip_tags(getImageDesc()))) { ?>
                <div class="photo-desc prose"><?php printImageDesc(); ?></div>
            <?php } ?>
            <p class="photo-album"><?php echo atelier_icon('camera'); ?> <a href="<?php echo html_encode(getAlbumURL()); ?>"><?php echo html_encode(getBareAlbumTitle()); ?></a></p>

            <?php
            if (atelier_option('zpB_show_exif', true)) {
                $exif = getImageMetaData($_current_image, true);
                if ($exif) {
                    ?>
                    <section class="side-block">
                        <h2 class="side-block__title"><?php echo atelier_icon('info'); ?> <?php echo html_encode(gettext('Image Info')); ?></h2>
                        <dl class="exif">
                            <?php foreach ($exif as $field => $value) { ?>
                                <div><dt><?php echo html_encode($_exifvars[$field][METADATA_DISPLAY_TEXT]); ?></dt><dd><?php echo html_encode(strval($value)); ?></dd></div>
                            <?php } ?>
                        </dl>
                    </section>
                    <?php
                }
            }
            ?>

            <?php if (extensionEnabled('rating')) { ?>
                <section class="side-block"><div class="rating"><?php printRating(); ?></div></section>
            <?php } ?>

            <?php if (getOption('zpB_show_tags') && getTags()) { ?>
                <section class="side-block"><div class="photo-tags"><?php printTags('links', NULL, 'tag-list', NULL); ?></div></section>
            <?php } ?>

            <?php atelier_printImageMap(); ?>

            <div class="side-actions">
                <?php if (npg_loggedin() && extensionEnabled('favoritesHandler')) { ?>
                    <div class="favorites" data-instance-placeholder="<?php echo html_encode(gettext('Favorites list name (optional)')); ?>"><?php printAddToFavorites($_current_image); ?></div>
                <?php } ?>
                <a class="button" href="<?php echo html_encode(getFullImageURL()); ?>" data-fancybox="single" title="<?php echo html_encode(getBareImageTitle()); ?>"><?php echo gettext('View full size'); ?></a>
            </div>
        </aside>
    </div>

    <?php
    if (atelier_option('atelier_similar', true)) {
        atelier_printSimilar();
    }
    if (extensionEnabled('comment_form')) {
        include('includes/print_comment.php');
    }
    ?>
</div>

<?php include('includes/footer.php'); ?>
