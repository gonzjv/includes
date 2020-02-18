<?php

function userIsLoggedIn() {
    if (isset($_POST['action']) and $_POST['action'] == 'login') {
        if (!isset($_POST['email']) or $_POST['email'] == '' or ! isset($_POST['password']) or $_POST['password'] == '') {
            $GLOBALS['loginError'] = 'Пожалуйста, заполните оба поля =)';
            return FALSE;
        }

        $password = md5($_POST['password'] . 'user');

        if (db_contains_user($_POST['email'], $password)) {
            $_SESSION['loggedIn'] = TRUE;
            $_SESSION['email'] = $_POST['email'];
            $_SESSION['password'] = $password;
            return TRUE;
        } else {
            unset($_SESSION['loggedIn']);
            unset($_SESSION['email']);
            unset($_SESSION['password']);
            $GLOBALS['loginError'] = 'The specified email address or password was incorrect.';
            return FALSE;
        }
    }

    if (isset($_POST['action']) and $_POST['action'] == 'logout') {
        unset($_SESSION['loggedIn']);
        unset($_SESSION['email']);
        unset($_SESSION['password']);
        header('Location: ' . $_POST['goto']);
        exit();
    }
    if (isset($_SESSION['loggedIn'])) {
        return db_contains_user($_SESSION['email'], $_SESSION['password']);
    }
}

function pass_ok() {
    if (isset($_POST['action']) and $_POST['action'] == 'sign_up' and $_POST['password'] !== $_POST['passConfirm']) {
        $GLOBALS['signUpError'] = 'Passwords in fields are not identical';
        return FALSE;
    } else {
        return TRUE;
    }
}

function sign_up() {
    if (isset($_POST['action']) and $_POST['action'] == 'sign_up' and pass_ok()) {
        include 'db.inc.php';
        $password = md5($_POST['password'] . 'user');
        try {
            $sql = 'INSERT INTO user SET 
            first_name= :first_name,
            last_name= :last_name,
            email=:email,
            phone=:phone,
            password=:password';
            $s = $pdo->prepare($sql);
            $s->bindValue(':first_name', $_POST['first_name']);
            $s->bindValue(':last_name', $_POST['last_name']);
            $s->bindValue(':email', $_POST['email']);
            $s->bindValue(':phone', $_POST['phone']);
            $s->bindValue(':password', $password);
            $s->execute();
        } catch (PDOException $e) {
            $error = 'Error when add user.';
            include 'error.html.php';
            exit();
        }
        return TRUE;
    } else {
        return FALSE;
    }
}

function db_contains_user($email, $password) {
    include 'db.inc.php';
    try {
        $sql = 'SELECT COUNT(*) FROM user
        WHERE email = :email AND password = :password';
        $s = $pdo->prepare($sql);
        $s->bindValue(':email', $email);
        $s->bindValue(':password', $password);
        $s->execute();
    } catch (PDOException $e) {
        $error = 'Error searching for user.';
        include 'error.html.php';
        exit();
    }

    $row = $s->fetch();

    if ($row[0] > 0) {
        try {
            $sql = 'SELECT first_name FROM user
        WHERE email = :email';
            $s = $pdo->prepare($sql);
            $s->bindValue(':email', $email);
            $s->execute();
        } catch (PDOException $e) {
            $error = 'Error searching for first_name.';
            include 'error.html.php';
            exit();
        }
        $row = $s->fetch();
        $_SESSION['first_name'] = $row['first_name'];

        return TRUE;
    } else {
        return FALSE;
    }
}

function user_has_role($role) {
    include 'db.inc.php';

    try {
        $sql = "SELECT COUNT(*) FROM user
        INNER JOIN userrole ON info.id = userid
        INNER JOIN role ON roleid = role.id
        WHERE email = :email AND role.id = :roleId";
        $s = $pdo->prepare($sql);
        $s->bindValue(':email', $_SESSION['email']);
        $s->bindValue(':roleId', $role);
        $s->execute();
    } catch (PDOException $e) {
        $error = 'Error searching for user roles.';
        include 'error.html.php';
        exit();
    }

    $row = $s->fetch();

    if ($row[0] > 0) {
        return TRUE;
    } else {
        return FALSE;
    }
}
