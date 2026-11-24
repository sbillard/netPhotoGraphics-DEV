<?php if (!empty($_atelier_autowrap)) { echo '</div>'; } ?>
        </main>

        <footer class="site-footer">
            <div class="site-footer__inner">
                <div class="site-footer__primary">
                    <div class="site-footer__branding"><?php echo html_encode(atelier_siteName()); ?></div>
                    <?php $_atelier_tag = trim((string) getOption('atelier_hero_text')); if ($_atelier_tag !== '') { ?>
                        <p class="site-footer__tagline"><?php echo html_encode($_atelier_tag); ?></p>
                    <?php } ?>
                    <ul class="site-footer__menu">
                        <?php if (extensionEnabled('daily-summary')) { ?>
                            <li><?php printDailySummaryLink(gettext('Daily summary'), '', '', ''); ?></li>
                        <?php } ?>
                        <?php
                        if (extensionEnabled('rss')) {
                            if ($_zenpage_news_enabled && getOption('RSS_articles')) {
                                echo '<li>';
                                printRSSLink('News', '', 'RSS ' . NEWS_LABEL, '', false, 'rss');
                                echo '</li>';
                            } else if (getOption('RSS_album_image')) {
                                echo '<li>';
                                printRSSLink('Gallery', '', 'RSS', '', false, 'rss');
                                echo '</li>';
                            }
                        }
                        ?>
                    </ul>
                </div>

                <?php if (atelier_option('zpB_show_stats', true)) { $stats = atelier_getStats(); ?>
                    <div class="site-footer__statistics">
                        <div class="site-statistic">
                            <span class="site-statistic__label"><?php echo gettext('Images with GPS coordinates'); ?></span>
                            <span class="site-statistic__value"><strong><?php echo number_format($stats['gps'], 0, ',', '&nbsp;'); ?></strong>&nbsp;(<?php echo $stats['gps_percent']; ?>&nbsp;%)</span>
                        </div>
                        <div class="site-statistic">
                            <span class="site-statistic__label"><?php echo gettext('Items with descriptions'); ?></span>
                            <span class="site-statistic__value"><strong><?php echo number_format($stats['described'], 0, ',', '&nbsp;'); ?></strong>&nbsp;(<?php echo $stats['described_percent']; ?>&nbsp;%)</span>
                        </div>
                    </div>
                <?php } ?>

                <div class="site-footer__secondary"><?php print_SW_Link(); ?></div>
            </div>
        </footer>

        <button type="button" class="scroll-top" hidden aria-label="<?php echo gettext('Top'); ?>"><?php echo atelier_icon('up', 22); ?></button>
        <?php npgFilters::apply('theme_body_close'); ?>
    </body>
</html>
