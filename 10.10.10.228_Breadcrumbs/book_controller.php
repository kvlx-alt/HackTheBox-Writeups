
"<?php

if($_SERVER['REQUEST_METHOD'] == \"POST\"){
    $out = \"\";
    require '../db/db.php';

    $title = \"\";
    $author = \"\";

    if($_POST['method'] == 0){
        if($_POST['title'] != \"\"){
            $title = \"%\".$_POST['title'].\"%\";
        }
        if($_POST['author'] != \"\"){
            $author = \"%\".$_POST['author'].\"%\";
        }
        
    
        $query = \"SELECT * FROM books WHERE title LIKE ? OR author LIKE ?\";
        $stmt = $con->prepare($query);
        $stmt->bind_param('ss', $title, $author);
        $stmt->execute();
        $res = $stmt->get_result();
        $out = mysqli_fetch_all($res,MYSQLI_ASSOC);
    }

    elseif($_POST['method'] == 1){
        $out = file_get_contents('../books/'.$_POST['book']);
    }

    else{
        $out = false;
    }

    echo json_encode($out);
}"
