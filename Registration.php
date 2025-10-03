<?php
session_start();

$conn = new mysqli('localhost', 'root', '', 'registration_form2');

if ($conn->connect_error) {
    die("Ошибка подключения: " . $conn->connect_error);
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $login = $_POST['login'];
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT * FROM users WHERE login = ?");
    $stmt->bind_param("s", $login);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        echo "<h3>Пользователь с таким логином уже существует!</h3>";
    } else {
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $conn->prepare("INSERT INTO users (login, password) VALUES (?, ?)");
        $stmt->bind_param("ss", $login, $hashed_password);

        if ($stmt->execute()) {
            echo "<h3>Регистрация прошла успешно!</h3>";
        } else {
            echo "<h3>Ошибка при регистрации: " . $stmt->error . "</h3>";
        }
    }

    $stmt->close();
}

$conn->close();
?>