<?php include('includes/header.php'); ?>

<?php if (is_NewsArticle()) { ?>

    <article class="article">
        <header class="article__head">
            <?php
            $_atelier_cats = getNewsCategories();
            ?>
            <p class="article__meta">
                <?php
                if ($_atelier_cats) {
                    $_firstCat = reset($_atelier_cats); // the array is not guaranteed to have an index 0
                    $_c = newCategory($_firstCat['titlelink']);
                    ?><a class="article__cat" href="<?php echo html_encode($_c->getLink()); ?>"><?php echo html_encode($_c->getTitle()); ?></a> · <?php
                }
                ?>
                <time datetime="<?php echo html_encode(date('c', strtotime($_CMS_current_article->getDateTime()))); ?>"><?php printNewsDate(); ?></time>
                · <?php printf(gettext('%u min read'), atelier_readingTime($_CMS_current_article->getContent())); ?>
            </p>
            <h1 class="article__title"><?php printNewsTitle(); ?></h1>
        </header>

        <div class="article__content prose-article">
            <?php
            printNewsContent();
            printCodeblock(1);
            ?>
        </div>

        <?php if (getNewsExtraContent()) { ?>
            <aside class="extra-content prose article__extra"><?php printNewsExtraContent(); ?></aside>
        <?php } ?>

        <?php if (count($_atelier_cats) > 1) { ?>
            <footer class="article__foot"><?php printNewsCategories('', '', 'tag-list'); ?></footer>
        <?php } ?>
    </article>

    <?php if (getPrevNewsURL() || getNextNewsURL()) { ?>
        <nav class="post-nav" aria-label="<?php echo html_encode(gettext('Other articles')); ?>">
            <?php if (getPrevNewsURL()) { $article_url = getPrevNewsURL(); ?>
                <a class="post-nav__item post-nav__item--prev" rel="prev" href="<?php echo html_encode($article_url['link']); ?>">
                    <small>← <?php echo gettext('Previous'); ?></small>
                    <span><?php echo html_encode(shortenContent($article_url['title'], $zpB_shorten_title_size, ' (...)')); ?></span>
                </a>
            <?php } else { ?><span></span><?php } ?>
            <?php if (getNextNewsURL()) { $article_url = getNextNewsURL(); ?>
                <a class="post-nav__item post-nav__item--next" rel="next" href="<?php echo html_encode($article_url['link']); ?>">
                    <small><?php echo gettext('Next'); ?> →</small>
                    <span><?php echo html_encode(shortenContent($article_url['title'], $zpB_shorten_title_size, ' (...)')); ?></span>
                </a>
            <?php } ?>
        </nav>
    <?php } ?>

    <div class="container container--narrow">
        <?php if (extensionEnabled('comment_form')) { include('includes/print_comment.php'); } ?>
    </div>

<?php } else { ?>

    <div class="container">
        <?php
        $_atelier_isRefs = atelier_isRefCategory();
        ?>
        <header class="page-header">
            <p class="eyebrow"><?php echo html_encode($_atelier_isRefs ? gettext('Clients') : gettext('Blog')); ?></p>
            <h1 class="page-title"><?php
                if ($_atelier_isRefs) {
                    echo html_encode($_CMS_current_category->getTitle());
                } else {
                    echo html_encode(NEWS_LABEL);
                    printCurrentNewsCategory(' | ' . gettext('Category') . ' : ');
                    printCurrentNewsArchive(' | ');
                }
                ?></h1>
            <?php if ($_atelier_isRefs && trim(strip_tags($_CMS_current_category->getDesc()))) { ?>
                <div class="page-description prose"><?php echo $_CMS_current_category->getDesc(); ?></div>
            <?php } ?>
        </header>

        <?php atelier_printNewsCategories(); ?>

        <?php if ($_atelier_isRefs) { ?>

            <div class="ref-grid ref-grid--page">
                <?php while (next_news()) { atelier_printRefCard($_CMS_current_article); } ?>
            </div>

        <?php } else { ?>

            <div class="story-list">
                <?php
                $_atelier_i = 0;
                $_atelier_ref = atelier_refCategory();
                while (next_news()) {
                    if ($_atelier_ref !== '' && !is_NewsCategory()) {
                        $skip = false;
                        foreach ($_CMS_current_article->getCategories() as $c) {
                            if ($c['titlelink'] === $_atelier_ref) {
                                $skip = true;
                                break;
                            }
                        }
                        if ($skip) {
                            continue;
                        }
                    }
                    atelier_printStoryCard($_CMS_current_article, ($_atelier_i === 0 && $_current_page == 1) ? 'large' : 'small');
                    $_atelier_i++;
                }
                ?>
            </div>

        <?php } ?>

        <nav class="pagination-wrapper"><?php printNewsPageListWithNav('»', '«', true, 'pagination', true, 7); ?></nav>
    </div>

<?php } ?>

<?php include('includes/footer.php'); ?>
