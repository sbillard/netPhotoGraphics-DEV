<?php
/*
 * Login / password screen in two halves: photo on the left, form on the right.
 * $_atelier_login_variant: 'login' (client area / user login) or 'album' (password protected album or page)
 */
$variant = isset($_atelier_login_variant) ? $_atelier_login_variant : 'login';
$blur = '';
// a protected Zenpage page / article / category (no album): no photo of the gallery, just the title and a lock
$zpObject = false;
if ($variant === 'album') { // Zenpage objects exist only on a Zenpage request, never on an album one
    foreach (array('_CMS_current_page', '_CMS_current_article', '_CMS_current_category') as $zpVar) {
        if (isset($GLOBALS[$zpVar]) && is_object($GLOBALS[$zpVar])) {
            $zpObject = $GLOBALS[$zpVar];
            break;
        }
    }
}
if ($variant === 'album' && !$zpObject && isset($_current_album) && is_object($_current_album) && atelier_option('atelier_blur_locked', false) && !empty($_current_album->getPassword())) {
    $blur = atelier_blurData($_current_album); // the cover of this album, blurred
}
$photo = ($blur === '' && !$zpObject) ? atelier_heroImage() : false;
$hint = isset($hint) ? $hint : '';
if ($variant === 'album') {
    $heading = gettext('Album is password protected');
    $text = gettext('Enter the password you received from the photographer.');
    $button = gettext('Open album');
    if ($zpObject) {
        $heading = gettext('This page is password protected');
        $button = gettext('Open page');
        $zpTitle = trim(strip_tags((string) $zpObject->getTitle()));
        if ($zpTitle !== '') {
            $text = $heading . '. ' . $text;
            $heading = $zpTitle;
        }
    }
    // say which album the visitor is unlocking: its title becomes the heading
    if (!$zpObject && isset($_current_album) && is_object($_current_album) && $_gallery_page == 'password.php' && !$_current_album->checkAccess()) {
        $albumTitle = trim(strip_tags($_current_album->getTitle()));
        if ($albumTitle !== '') {
            $text = $heading . '. ' . $text;
            $heading = $albumTitle;
        }
    }
} else {
    $heading = gettext('Welcome back');
    $text = trim((string) getOption('atelier_login_text'));
    if ($text === '') {
        $text = gettext('Enter your user name and password.');
    }
}
$linkText = trim((string) getOption('atelier_login_link_text'));
if ($linkText === '') {
    $linkText = gettext('No access? Write to me');
}
$linkUrl = trim((string) getOption('atelier_login_link_url'));
if ($linkUrl === '' && extensionEnabled('contact_form')) {
    $linkUrl = getCustomPageURL('contact');
}
?>
<div class="login-split login-split--<?php echo $variant; ?>"<?php echo $variant === 'album' ? ' data-button="' . html_encode($button) . '"' : ''; ?>>
    <div class="login-split__photo<?php echo $zpObject ? ' login-split__photo--plain' : ''; ?>" aria-hidden="true">
        <?php if ($zpObject) { echo atelier_icon('lock', 72); } ?>
        <?php if ($blur !== '') { ?>
            <img class="is-blurred" style="--blur:<?php echo atelier_blurLevel()[1] * 2; ?>px" src="<?php echo html_encode($blur); ?>" alt="">
        <?php } elseif ($photo) { ?>
            <img loading="lazy" decoding="async" src="<?php echo html_encode($photo->getCustomImage(array('width' => 900, 'height' => 1200, 'cw' => 900, 'ch' => 1200, 'thumb' => true))); ?>" alt="">
        <?php } ?>
        <span class="login-split__brand"><?php echo html_encode(atelier_siteName()); ?></span>
    </div>
    <div class="login-split__form">
        <p class="login-split__eyebrow"><?php echo atelier_icon($variant === 'album' ? 'lock' : 'user'); ?> <?php echo html_encode($variant === 'album' ? ($zpObject ? gettext('Protected page') : gettext('Client gallery')) : gettext('Client area')); ?></p>
        <h1 class="login-split__title"><?php echo html_encode($heading); ?></h1>
        <p class="login-split__text"><?php echo html_encode($text); ?></p>
        <?php // the user login (menu) always needs the user name (administrators); the option only concerns album passwords
        printPasswordForm($variant === 'album' ? $hint : '', $variant === 'album' ? atelier_option('atelier_login_user', false) : true, false, NULL, false); ?>
        <?php if ($linkUrl !== '') { ?>
            <p class="login-split__help"><a href="<?php echo html_encode($linkUrl); ?>"><?php echo html_encode($linkText); ?></a></p>
        <?php } ?>
    </div>
</div>
