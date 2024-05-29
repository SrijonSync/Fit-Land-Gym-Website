<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Check if the form was submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Assign form data to variables
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $Name = filter_var($_POST['Name'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $Gender = filter_var($_POST['gender'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $contactNumber = filter_var($_POST['Contact Number'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $formPassword = $_POST['password']; // Rename this variable to avoid conflict
    $address = filter_var($_POST['Address'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $nationalId = filter_var($_POST['nationalId'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $birthDate = filter_var($_POST['birthDate'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $age = filter_input(INPUT_POST, 'age', FILTER_SANITIZE_NUMBER_INT);
    $image = $_FILES['image'];

    // Database credentials
    $dbServerName = "localhost";
    $dbUserName = "root";
    $dbPassword = ""; // Database password, make sure this is correct
    $dbName = "fit_land";

    // Hash the form password
    $hashed_password = password_hash($formPassword, PASSWORD_DEFAULT);

    // Create database connection
    $conn = new mysqli($dbServerName, $dbUserName, $dbPassword, $dbName);

    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Check if the file was uploaded without errors
    if (isset($image) && $image['error'] == UPLOAD_ERR_OK) {
        // Read the image content
        $imageContent = file_get_contents($image['tmp_name']);

        // Prepare the insert statement (ensure your column names are correct)
        $stmt = $conn->prepare("INSERT INTO registration (Name, Gender, Email, Contact Number, Password, Address, NationalID, BirthDate, Age, Image) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

        // Initialize the null variable for the blob
        $null = NULL;

        // Bind the parameters
        $stmt->bind_param("ssssssisib", $Name, $Gender, $email, $Contact Number, $password, $address, $nationalId, $birthDate, $age, );

        // Send the blob data separately
        $stmt->send_long_data(9, $imageContent);

        // Execute the prepared statement
        if ($stmt->execute()) {
            echo "Registration successful...";
        } else {
            echo "Error in registration: " . htmlspecialchars($stmt->error);
        }

        // Close statement and connection
        $stmt->close();
    } else {
        echo "Error in file upload: " . $image['error'];
    }

    // Close database connection
    $conn->close();
}
?>



