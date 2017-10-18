<?php
try
{//connection
$pdo = new PDO('mysql:host=localhost;dbname=football', 'all',
'qwe');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec('SET NAMES "utf8"');
}	
catch (PDOException $e)
{//connect error
$error = 'Невозможно подключиться к серверу баз данных:' .
$e->getMessage();
include 'error.html.php';
exit();
}