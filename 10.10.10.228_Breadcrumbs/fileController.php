<?php
$ret = \"\";
require \"..\/vendor\/autoload.php\";
use \\Firebase\\JWT\\JWT;
session_start();

function validate(){
    $ret = false;
    $jwt = $_COOKIE['token'];

    $secret_key = '6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e';
    $ret = JWT::decode($jwt, $secret_key, array('HS256'));   
    return $ret;
}

if($_SERVER['REQUEST_METHOD'] === \"POST\"){
    $admins = array(\"paul\");
    $user = validate()->data->username;
    if(in_array($user, $admins) && $_SESSION['username'] == \"paul\"){
        error_reporting(E_ALL & ~E_NOTICE);
        $uploads_dir = '..\/uploads';
        $tmp_name = $_FILES[\"file\"][\"tmp_name\"];
        $name = $_POST['task'];

        if(move_uploaded_file($tmp_name, \"$uploads_dir\/$name\")){
            $ret = \"Success. Have a great weekend!\";
        }     
        else{
            $ret = \"Missing file or title :(\" ;
        }
    }
    else{
        $ret = \"Insufficient privileges. Contact admin or developer to upload code. Note: If you recently registered, please wait for one of our admins to approve it.\";
    }

    echo $ret;
}
