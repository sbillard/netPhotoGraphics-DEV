<?php include('includes/header.php'); ?>

<div class="container">
    <header class="page-header">
        <p class="eyebrow"><?php echo gettext('Portfolio'); ?></p>
        <h1 class="page-title"><?php echo getGalleryTitle() ? html_encode(getBareGalleryTitle()) : gettext('Portfolio'); ?></h1>
        <?php if (!getOption('zpB_homepage') && getGalleryDesc()) { ?>
            <div class="page-description prose"><?php printGalleryDesc(); ?></div>
        <?php } ?>
    </header>

    <?php if (isAlbumPage()) { include('includes/print_album_thumb.php'); } ?>
    <?php include('includes/print_pagination.php'); ?>
</div>

<?php include('includes/footer.php'); ?>
