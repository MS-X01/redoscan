<?php
// Hardened version of examples/vulnerable/UserController.php.

class UserController {

    public function search($conn) {
        // Prepared statement with a bound parameter: no interpolation at all.
        $id = $_GET['id'];
        $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
    }

    public function backup($dir) {
        // escapeshellarg() neutralizes shell metacharacters in the argument.
        shell_exec("tar -czf backup.tar.gz " . escapeshellarg($dir));
    }

    public function loadSession($blob) {
        // json_decode can't construct arbitrary PHP objects from the input.
        return json_decode($blob, true);
    }

    public function hashPassword($password) {
        // password_hash() uses bcrypt by default, with a random salt.
        return password_hash($password, PASSWORD_DEFAULT);
    }

    private const ALLOWED_PAGES = ['home', 'about', 'contact'];

    public function render() {
        // Validate against an allow-list instead of trusting the filename.
        $page = $_GET['page'];
        if (!in_array($page, self::ALLOWED_PAGES, true)) {
            http_response_code(400);
            return;
        }
        include(__DIR__ . "/pages/{$page}.php");
    }

    public function fetchThumbnail($url) {
        // Validate the host against an allow-list before fetching it.
        $host = parse_url($url, PHP_URL_HOST);
        if (!in_array($host, ['images.example.com'], true)) {
            http_response_code(400);
            return null;
        }
        return file_get_contents($url);
    }
}

// Policy/Gate check before the resource is returned.
Route::get('/orders/{id}', function ($id) {
    $order = Order::findOrFail($id);
    Gate::authorize('view', $order);
    return $order;
});
