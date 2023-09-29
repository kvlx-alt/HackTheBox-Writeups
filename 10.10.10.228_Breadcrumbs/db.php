"<?php

$host=\"localhost\";
$port=3306;
$user=\"bread\";
$password=\"jUli901\";
$dbname=\"bread\";

$con = new mysqli($host, $user, $password, $dbname, $port) or die ('Could not connect to the database server' . mysqli_connect_error());
?>
"
