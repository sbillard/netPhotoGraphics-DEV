<?php include('includes/header.php'); ?>

<?php
$hero = atelier_heroImage();
$heroTitle = trim((string) getOption('atelier_hero_title'));
if ($heroTitle === '') {
    $heroTitle = getBareGalleryTitle();
}
$heroText = trim((string) getOption('atelier_hero_text'));
$heroButton = trim((string) getOption('atelier_hero_button'));
if ($heroButton === '') {
    $heroButton = gettext('See the portfolio');
}
?>
<section class="hero<?php echo $hero ? '' : ' hero--plain'; ?>">
    <?php if ($hero) { ?>
        <img class="hero__image" fetchpriority="high" decoding="async"
             src="<?php echo html_encode($hero->getCustomImage(array('width' => 2000, 'height' => 1000, 'cw' => 2000, 'ch' => 1000, 'thumb' => true))); ?>"
             alt="<?php echo html_encode($hero->getTitle()); ?>">
    <?php } ?>
    <div class="hero__content">
        <h1 class="hero__title"><?php echo html_encode($heroTitle); ?></h1>
        <?php if ($heroText !== '') { ?><p class="hero__text"><?php echo html_encode($heroText); ?></p><?php } ?>
        <a class="button button--primary button--lg" href="<?php echo html_encode(getCustomPageURL('gallery')); ?>"><?php echo html_encode($heroButton); ?> <?php echo atelier_icon('arrow'); ?></a>
    </div>
</section>

<div class="container">

    <?php atelier_printHomeStories(); ?>

    <?php atelier_printHomePortfolio(); ?>

    <?php
    $aboutLink = trim((string) getOption('atelier_about_page'));
    if ($aboutLink !== '' && class_exists('CMS')) {
        $about = newPage($aboutLink);
        if ($about && $about->exists && $about->checkAccess()) {
            $aboutContent = $about->getContent();
            $aboutImg = atelier_firstImage($aboutContent);
            ?>
            <section class="home-section about<?php echo $aboutImg ? '' : ' about--noimg'; ?>">
                <?php if ($aboutImg) { ?>
                    <img class="about__photo" loading="lazy" decoding="async" src="<?php echo html_encode($aboutImg[0]); ?>" alt="<?php echo html_encode($aboutImg[1]); ?>">
                <?php } ?>
                <div class="about__body">
                    <p class="eyebrow"><?php echo gettext('About me'); ?></p>
                    <h2 class="about__title"><?php echo html_encode($about->getTitle()); ?></h2>
                    <p class="about__text"><?php echo html_encode(atelier_excerpt(atelier_withoutFirstImage($aboutContent), 420)); ?></p>
                    <a class="button" href="<?php echo html_encode($about->getLink()); ?>"><?php echo gettext('More about me'); ?> <?php echo atelier_icon('arrow'); ?></a>
                </div>
            </section>
            <?php
        }
    }
    ?>

    <?php atelier_printHomeReferences(); ?>

    <?php if (trim(strip_tags(getGalleryDesc()))) { ?>
        <section class="home-section"><div class="prose prose--center"><?php printGalleryDesc(); ?></div></section>
    <?php } ?>

    <?php atelier_printHomeStats(); ?>

</div>

<?php include('includes/footer.php'); ?>
