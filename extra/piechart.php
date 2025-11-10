<?php
/********************************************************************
piechart.php - creates pie chart for CIS F5 Benchmark Reports

Version: 0.1
Last Modified: 10 November 2025
Author: Niels van Sluis

This Sample Software provided by the author is for illustrative
purposes only which provides customers with programming information
regarding the products. This software is supplied "AS IS" without any
warranties and support.

The author assumes no responsibility or liability for the use of the
software, conveys no license or title under any patent, copyright, or
mask work right to the product.

The author reserves the right to make changes in the software without
notification. The author also make no representation or warranty that
such application will be suitable for the specified use without
further testing or modification.
********************************************************************/

$correct = 33;
$correct_value = 120;
$exceptions_value = 120;
$incorrect_value = 120;

if (isset($_GET['c']) && isset($_GET['e']) && isset($_GET['i'])) {
  $correct = intval($_GET['c']);
  $exceptions = intval($_GET['e']);
  $incorrect = intval($_GET['i']);

  if( $correct < 0 ) { $correct = 0; }
  if( $exceptions < 0 ) { $exceptions = 0; }
  if( $incorrect < 0 ) { $incorrect = 0; }

  // the total can't be greater than 100
  if( ($correct + $exceptions + $incorrect) <= 100) {
      $correct_value = (($correct * 360) / 100);
      $exceptions_value = (($exceptions * 360) / 100);
      $incorrect_value = (($incorrect * 360) / 100);
    }
}

$end_degrees_first_pie = 270 + $correct_value;
$end_degrees_second_pie = $end_degrees_first_pie + $exceptions_value;
$end_degrees_third_pie = $end_degrees_second_pie + $incorrect_value;

// Create ImagickDraw object
$draw = new ImagickDraw();
$draw->setStrokeColor('Black');
$draw->setFillColor('#eeeeee');
$draw->setStrokeWidth(1);

// Draw background circle
$draw->arc(3,3,197,197,0,360);

// Draw green pie - first
// Starts at 270 degrees
$draw->setStrokeWidth(22);
$draw->setStrokeColor('Green');
//$draw->arc(15,15,185,185,270,360);
$draw->arc(15,15,185,185,270,$end_degrees_first_pie);

// Draw orange pie - second
$draw->setStrokeWidth(22);
$draw->setStrokeColor('Orange');
//$draw->arc(15,15,185,185,0,90);
$draw->arc(15,15,185,185,$end_degrees_first_pie,$end_degrees_second_pie);

// Draw red pie - third
$draw->setStrokeWidth(22);
$draw->setStrokeColor('red');
//$draw->arc(15,15,185,185,90,270);
$draw->arc(15,15,185,185,$end_degrees_second_pie,$end_degrees_third_pie);

// Draw inner circle
$draw->setStrokeColor('Black');
$draw->setFillColor('#333333');
$draw->setStrokeWidth(1);
$draw->arc(27,27,173,173,0,360);

// Add score
$draw->setStrokeAntialias(true);
$draw->setTextAntialias(true);
$draw->setFont('fonts/LibraSans-Bold.ttf');
$draw->setFontSize(30);
$draw->setStrokeWidth(1);
$draw->setStrokeColor('#eee');
$draw->setFillColor('#fff');
$draw->annotation(57,70,"Score");

if($correct <= 1) {
  $draw->setFontSize(80);
  $draw->annotation(63,135,"{$correct}");
  $draw->setFontSize(40);
  $draw->annotation(100,108,"%");
}
else if($correct > 1 && $correct < 100) {
  $draw->setFontSize(80);
  $draw->annotation(43,135,"{$correct}");
  $draw->setFontSize(40);
  $draw->annotation(130,108,"%");
}
else {
  $draw->setFontSize(55);
  $draw->annotation(40,125,"{$correct}");
  $draw->setFontSize(30);
  $draw->annotation(132,108,"%");
}

// Create an image object
$image = new Imagick();
$image->newImage(200, 200, new ImagickPixel('transparent'));
$image->setImageFormat("png");

// Use drawImage function
$image->drawImage($draw);

// Send the image to the browser
header("Content-Type: image/png");
echo $image->getImageBlob();
$image->clear();
?>
