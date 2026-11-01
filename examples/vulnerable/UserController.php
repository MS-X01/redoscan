<?php
// Intentionally vulnerable PHP code for demo and CI purposes.
// See examples/safe/UserController.php for the corrected version.

class UserController {

    public function search($conn) {
        // CWE-89: SQL built with a directly-interpolated variable
        $id = $_GET['id'];
        mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
    }

    public function backup() {
        // CWE-78: shell command built with a directly-interpolated variable
        shell_exec("tar -czf backup.tar.gz " . $_GET['dir']);
    }

    public function loadSession($blob) {
        // CWE-502: unserialize() on a non-literal (attacker-controlled) value
        return unserialize($blob);
    }

    public function hashPassword($password) {
        // CWE-327: MD5 is not a password hash
        return md5($password);
    }

    public function render() {
        // CWE-22: include() built directly from request input (LFI)
        include($_GET['page']);
    }

    public function fetchThumbnail() {
        // CWE-918: outbound request built directly from request input
        return file_get_contents($_GET['url']);
    }
}

// CWE-639: route takes an id-like parameter, no auth/ownership check nearby
Route::get('/orders/{id}', 'OrderController@show');
