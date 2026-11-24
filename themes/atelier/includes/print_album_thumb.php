<div class="tile-grid tile-grid--albums">
    <?php
    while (next_album()) {
        $n = (int) $_current_album->getNumImages();
        ?>
        <a class="tile tile--wide" href="<?php echo html_encode(getAlbumURL()); ?>" title="<?php echo html_encode(getBareAlbumTitle()); ?>">
            <span class="tile__media">
                <?php
                if (atelier_albumLocked($_current_album)) {
                    atelier_printLockedThumb($_current_album, getBareAlbumTitle());
                } else {
                    printCustomAlbumThumbImage(getBareAlbumTitle(), array(
                    'width' => getOption('zpB_album_thumb_width'),
                    'height' => getOption('zpB_album_thumb_height'),
                    'cw' => getOption('zpB_album_thumb_width'),
                    'ch' => getOption('zpB_album_thumb_height')), 'tile__image');
                }
                ?>
            </span>
            <span class="tile__title"><?php echo html_encode(getBareAlbumTitle()); ?></span>
            <?php if ($n > 0) { ?><span class="tile__count"><?php printf(ngettext('%u image', '%u images', $n), $n); ?></span><?php } ?>
        </a>
    <?php } ?>
</div>
