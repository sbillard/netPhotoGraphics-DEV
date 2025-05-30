<?php

/**
 * The configuration parameters for TinyMCE.
 *
 * CMS plugin ribbon-light configuration
 * @author Stephen Billard (sbillard)
 */
$MCEselector = "textarea.content,textarea.desc,textarea.extracontent";
$MCEplugins = "advlist autolink lists link image charmap anchor pagebreak " .
				"searchreplace visualchars wordcount visualblocks  code fullscreen " .
				"insertdatetime media nonbreaking save table directionality " .
				"emoticons pasteobj help";
$MCEtoolbars = array();
$MCEstatusbar = true;
$MCEmenubar = true;
include(TINYMCE . '/config/config.js.php');
