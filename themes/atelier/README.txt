Atelier 1.0 - blog and portfolio theme for netPhotoGraphics
===========================================================
Author: Martin Kroul. Developed in collaboration with Claude (AI assistant by Anthropic).
Built on the tested structure of the Nova theme and on the ideas of Zenpage. GPL v2 or later.

INSTALL
 1. Copy the folder "atelier" to /themes/ and select it in Admin > Themes.
 2. Enable the plugins you want: zenpage (blog, pages), comment_form, rating, favoritesHandler,
    contact_form, openStreetMap (maps), user_login-out.
 3. Open the theme options (Admin > Themes > Atelier > options) and choose the colour scheme.

WHAT IT DOES
 - Home: hero image + headline + button, "From the blog" (1 big + small stories), "Portfolio" (4 albums),
   "About me" block (a Zenpage page), strip with references, optional statistics and tag cloud.
 - Blog = Zenpage news: cards, categories, narrow reading column; an image alone on a line becomes a
   full-width figure, several images in one paragraph become an inline gallery; previous/next, comments.
 - Pages: tables and lists are styled (price list = an ordinary page with a table).
 - References: one news category (set its titlelink in the options). One article = one reference:
   title = name(s), first image = small photo, text = quote. Shown as cards, no stars.
 - Albums: masonry (aspect ratios kept), filter chips by tags of the images on the page, pagination, lightbox.
 - Photo page: big photo left; title, description, shooting data, rating, tags, map, favorites on the right;
   similar photos (shared tags, otherwise the same album); comments.
 - Photo map page (/page/photomap): all geotagged photos, loaded by viewport (port of the Nova map).
 - Login / password-protected album: two halves (photo + form), password only (user name optional).
   Texts and the help link are editable in the options. Registration link is hidden by default.
 - Open Graph / Twitter meta for articles, pages, albums and photos.
 - Six colour schemes (Terracotta, Forest, Ocean, Plum, Sand, Graphite), each with a light and a dark variant,
   plus "Custom accent colour". Visitors only switch light/dark (optional), they never choose colours.

COLOURS AND CONTRAST
 css/schemes.css holds the colour schemes; every pair has been checked for WCAG AA
 (text 7:1, muted text 4.5:1, accent 4.5:1, text on accent 4.5:1, form borders 3:1).
 A custom accent that is too light/dark is not rejected: the nearest colour (same hue) that reaches 4.5:1
 on the light and on the dark background is used, and the options page shows the result live.

NOTES
 - Client galleries = ordinary netPhotoGraphics password protected albums (+ watermarks), nothing special.
 - Thumbnails on album pages are not cropped (masonry); thumbnail size is set by the theme (640 px).
 - Home photo pools are cached (random 6 h, latest 1 h) and the tag cloud/statistics 6 h.
