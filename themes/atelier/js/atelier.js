/* Atelier theme – vanilla JS (no framework needed except Fancybox's jQuery) */
(function () {
    'use strict';

    function ready(fn) {
        if (document.readyState !== 'loading') {
            fn();
        } else {
            document.addEventListener('DOMContentLoaded', fn);
        }
    }

    ready(function () {
        var $ = function (s, c) { return (c || document).querySelector(s); };

        /* tell assistive technology which menu item is the current page */
        document.querySelectorAll('.site-nav__list .active > a, .site-nav__list a.active').forEach(function (a) {
            a.setAttribute('aria-current', 'page');
        });

        /* mobile menu */
        var toggle = $('.nav-toggle'), nav = $('#site-nav');
        if (toggle && nav) {
            toggle.addEventListener('click', function () {
                var open = nav.classList.toggle('is-open');
                toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
            });
        }

        /* dark mode toggle (choice is remembered in this browser) */
        var themeBtn = $('.theme-toggle');
        if (themeBtn) {
            var root = document.documentElement;
            var current = function () {
                return root.getAttribute('data-theme') ||
                    (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
            };
            themeBtn.setAttribute('aria-pressed', current() === 'dark' ? 'true' : 'false');
            themeBtn.addEventListener('click', function () {
                var next = current() === 'dark' ? 'light' : 'dark';
                root.setAttribute('data-theme', next);
                themeBtn.setAttribute('aria-pressed', next === 'dark' ? 'true' : 'false');
                try { localStorage.setItem('atelier-theme', next); } catch (e) {}
            });
            /* follow the system while the visitor has not chosen */
            if (window.matchMedia) {
                window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function (ev) {
                    var stored = null;
                    try { stored = localStorage.getItem('atelier-theme'); } catch (e) {}
                    if (!stored) {
                        root.setAttribute('data-theme', ev.matches ? 'dark' : 'light');
                    }
                });
            }
        }

        /* dialogs (login, EXIF) */
        document.addEventListener('click', function (e) {
            var opener = e.target.closest('[data-dialog-open]');
            if (opener) {
                var d = document.getElementById(opener.getAttribute('data-dialog-open'));
                if (d && typeof d.showModal === 'function') {
                    e.preventDefault();
                    d.showModal();
                }
                return;
            }
            var closer = e.target.closest('[data-dialog-close]');
            if (closer) {
                var dlg = closer.closest('dialog');
                if (dlg) { dlg.close(); }
                return;
            }
            if (e.target.tagName === 'DIALOG') { /* click on backdrop */
                e.target.close();
            }
        });

        /* failed login -> reopen the dialog */
        var login = document.getElementById('login-dialog');
        if (login && login.querySelector('.alert, .errorbox') && typeof login.showModal === 'function') {
            login.showModal();
        }

        /* favorites: label the optional list-name field */
        document.querySelectorAll('.favorites[data-instance-placeholder]').forEach(function (box) {
            var ph = box.getAttribute('data-instance-placeholder');
            box.querySelectorAll('input.favorite_instance').forEach(function (input) {
                input.placeholder = ph;
                input.setAttribute('aria-label', ph);
            });
        });


        /* password protected album: the button says what it does */
        var albumForm = $('.login-split--album');
        if (albumForm) {
            var label = albumForm.getAttribute('data-button');
            albumForm.querySelectorAll('#loginform button[type="submit"], #loginform input[type="submit"]').forEach(function (b) {
                if (!label) { return; }
                if (b.tagName === 'INPUT') { b.value = label; } else { b.textContent = label; }
            });
        }

        /* album filter chips (tags of the photos on this page) */
        var bar = $('[data-filter-bar]'), wall = $('.masonry[data-filterable]');
        if (bar && wall) {
            bar.addEventListener('click', function (e) {
                var chip = e.target.closest('[data-filter]');
                if (!chip) { return; }
                var tag = chip.getAttribute('data-filter');
                bar.querySelectorAll('[data-filter]').forEach(function (c) { c.classList.toggle('is-active', c === chip); });
                wall.querySelectorAll('.shot').forEach(function (fig) {
                    var tags = [];
                    try { tags = JSON.parse(fig.getAttribute('data-tags') || '[]'); } catch (x) {}
                    var show = !tag || tags.indexOf(tag) > -1;
                    fig.hidden = !show;
                    var a = fig.querySelector('[data-fancybox]');
                    if (a) { if (show) { a.setAttribute('data-fancybox', 'images'); } else { a.removeAttribute('data-fancybox'); } }
                });
            });
        }

        /* small map of the photo */
        var pm = document.getElementById('atelier-photomap');
        if (pm && window.L) {
            var pos = [parseFloat(pm.getAttribute('data-lat')), parseFloat(pm.getAttribute('data-lon'))];
            var m = L.map(pm, {scrollWheelZoom: false}).setView(pos, 12);
            L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {maxZoom: 19, attribution: pm.getAttribute('data-attribution')}).addTo(m);
            L.circleMarker(pos, {radius: 9, weight: 3, color: '#fff', fillColor: getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#1b5d8f', fillOpacity: 1}).addTo(m);
        }

        /* scroll to top */
        var top = $('.scroll-top');
        if (top) {
            var onScroll = function () { top.hidden = window.scrollY < 600; };
            window.addEventListener('scroll', onScroll, {passive: true});
            top.addEventListener('click', function () { window.scrollTo({top: 0, behavior: 'smooth'}); });
            onScroll();
        }

        /* keyboard navigation: ← → on image and news article pages */
        var prev = $('a[rel="prev"]'), next = $('a[rel="next"]');
        if (prev || next) {
            document.addEventListener('keydown', function (e) {
                if (e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) { return; }
                if (document.querySelector('.fancybox-is-open, dialog[open]')) { return; }
                var t = e.target;
                if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) { return; }
                if (e.key === 'ArrowRight' && next) { window.location.href = next.href; }
                if (e.key === 'ArrowLeft' && prev) { window.location.href = prev.href; }
            });
        }
    });
})();
