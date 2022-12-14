<?php

use phpcms\libs\classes\checkcode;

pc_base::session_start();

$checkcode = new checkcode();
if (isset($_GET['code_len']) && intval($_GET['code_len'])) {
    $checkcode->code_len = intval($_GET['code_len']);
}
if ($checkcode->code_len > 8 || $checkcode->code_len < 2) {
    $checkcode->code_len = 4;
}
if (isset($_GET['font_size']) && intval($_GET['font_size'])) {
    $checkcode->font_size = intval($_GET['font_size']);
}
if (isset($_GET['width']) && intval($_GET['width'])) {
    $checkcode->width = intval($_GET['width']);
}
if ($checkcode->width <= 0) {
    $checkcode->width = 130;
}

if (isset($_GET['height']) && intval($_GET['height'])) {
    $checkcode->height = intval($_GET['height']);
}
if ($checkcode->height <= 0) {
    $checkcode->height = 50;
}
$max_width = $checkcode->code_len * 28;
$max_height = $checkcode->font_size * 2;
if ($checkcode->width > $max_width) {
    $checkcode->width = $max_width;
}
if ($checkcode->height > $max_height) {
    $checkcode->height = $max_height;
}

if (isset($_GET['font_color']) && trim(urldecode($_GET['font_color'])) && preg_match('/(^#[a-z0-9]{6}$)/im', trim(urldecode($_GET['font_color'])))) {
    $checkcode->font_color = trim(urldecode($_GET['font_color']));
}
if (isset($_GET['background']) && trim(urldecode($_GET['background'])) && preg_match('/(^#[a-z0-9]{6}$)/im', trim(urldecode($_GET['background'])))) {
    $checkcode->background = trim(urldecode($_GET['background']));
}
$checkcode->doimage();
$_SESSION['code'] = $checkcode->get_code();
