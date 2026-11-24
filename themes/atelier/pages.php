<?php include('includes/header.php'); ?>

<div class="container container--narrow">
    <header class="page-header">
        <h1 class="page-title"><?php printPageTitle(); ?></h1>
    </header>

    <?php if (hasPages()) { atelier_printSubPages(); } ?>

    <article class="article page-article">
        <div class="article__content prose-article">
            <?php printPageContent(); ?>
            <?php printCodeblock(1); ?>
        </div>
        <?php if (getPageExtraContent()) { ?>
            <aside class="extra-content prose article__extra"><?php printPageExtraContent(); ?></aside>
        <?php } ?>
    </article>

    <?php if (extensionEnabled('comment_form')) { include('includes/print_comment.php'); } ?>
</div>

<?php include('includes/footer.php'); ?>
