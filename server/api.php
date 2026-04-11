<?php

/**
 * STrans VPN Server — Remote Control API
 * No authentication required.
 *
 * Routes:
 *   POST   ?action=restart                       — restart strans-server service
 *   GET    ?action=users                         — get users.json
 *   POST   ?action=users                         — add new user (JSON body = user object)
 *   PATCH  ?action=users&id=<uuid>               — update user by id field (merge keys)
 *   GET    ?action=settings                      — get settings.json
 *   PATCH  ?action=settings                      — update settings.json (merge keys); restarts if host/port changed
 *   GET    ?action=gateways                      — list gateways from settings.json
 *   POST   ?action=gateways                      — install a gateway (body: {id,name,type,host,active,settings})
 *   DELETE ?action=gateways&id=<uuid>            — stop/remove a gateway and clean systemd
 *   GET    ?action=logs[&date=20260409][&files[]=20260409_125524] — get logs for a date
 *   GET    ?action=statistics[&date=2026-04-09]  — get statistics entries for a date
 */

define('SERVER_DIR', __DIR__);
define('USERS_FILE',      SERVER_DIR . '/users.json');
define('SETTINGS_FILE',   SERVER_DIR . '/settings.json');
define('STATISTICS_FILE', SERVER_DIR . '/statistics.json');
define('LOGS_DIR',        SERVER_DIR . '/logs');
define('SERVICE_NAME',    'strans-server');

require_once __DIR__ . '/gateway_generator.php';

header('Content-Type: application/json; charset=utf-8');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function ok(mixed $data = null): never
{
    echo json_encode(['ok' => true, 'data' => $data], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

function err(string $message, int $code = 400): never
{
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

function method(): string
{
    return strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
}

function body(): array
{
    $raw = file_get_contents('php://input');
    if (empty($raw)) return [];
    $decoded = json_decode($raw, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        err('Invalid JSON body: ' . json_last_error_msg());
    }
    return is_array($decoded) ? $decoded : [];
}

function readJson(string $path): array
{
    if (!file_exists($path)) return [];
    $content = file_get_contents($path);
    $data = json_decode($content, true);
    return is_array($data) ? $data : [];
}

function writeJson(string $path, mixed $data): void
{
    $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    $result = @file_put_contents($path, $json);
    if ($result === false) {
        err("Cannot write to {$path} — check file/directory permissions", 500);
    }
}

function restartService(): string
{
    $output = shell_exec('sudo systemctl restart ' . escapeshellarg(SERVICE_NAME) . ' 2>&1');
    return trim((string)$output);
}

// ─── Route dispatch ───────────────────────────────────────────────────────────

$action = trim($_GET['action'] ?? '');
if ($action === '') {
    err('Missing ?action parameter', 400);
}

// ─── restart ──────────────────────────────────────────────────────────────────

if ($action === 'restart') {
    if (method() !== 'POST') err('Use POST', 405);

    $out = restartService();
    ok(['message' => 'Restart command sent', 'output' => $out]);
}

// ─── users ────────────────────────────────────────────────────────────────────

if ($action === 'users') {
    $m = method();

    // GET — return users.json
    if ($m === 'GET') {
        if (!file_exists(USERS_FILE)) ok([]);
        ok(readJson(USERS_FILE));
    }

    // POST — add new user
    if ($m === 'POST') {
        $user = body();
        if (empty($user)) err('Request body is empty or not a JSON object');

        $users = file_exists(USERS_FILE) ? readJson(USERS_FILE) : [];
        if (!is_array($users)) $users = [];

        $users[] = $user;
        writeJson(USERS_FILE, $users);

        ok(['message' => 'User added', 'user' => $user]);
    }

    // PATCH — update existing user by id field (UUID)
    if ($m === 'PATCH') {
        $id = trim($_GET['id'] ?? '');
        if ($id === '') err('Missing ?id parameter');

        $patch = body();
        if (empty($patch)) err('Request body is empty or not a JSON object');

        if (!file_exists(USERS_FILE)) err('users.json not found', 404);

        $users = readJson(USERS_FILE);
        if (!is_array($users)) err('users.json is malformed', 500);

        $found = false;
        foreach ($users as &$entry) {
            if (!is_array($entry)) continue;
            if (($entry['id'] ?? '') === $id) {
                // Merge: existing keys updated, new keys added
                foreach ($patch as $k => $v) {
                    $entry[$k] = $v;
                }
                $found = true;
                break;
            }
        }
        unset($entry);

        if (!$found) err("User '{$id}' not found", 404);

        writeJson(USERS_FILE, $users);
        ok(['message' => "User '{$id}' updated"]);
    }

    err('Method not allowed', 405);
}

// ─── settings ─────────────────────────────────────────────────────────────────

if ($action === 'settings') {
    $m = method();

    // GET — return settings.json
    if ($m === 'GET') {
        if (!file_exists(SETTINGS_FILE)) ok([]);
        ok(readJson(SETTINGS_FILE));
    }

    // PATCH — merge settings, restart service if host or port changed
    if ($m === 'PATCH') {
        $patch = body();
        if (empty($patch)) err('Request body is empty or not a JSON object');

        // Load existing or create empty
        $settings = file_exists(SETTINGS_FILE) ? readJson(SETTINGS_FILE) : [];
        if (!is_array($settings)) $settings = [];

        $hostPortChanged = false;
        foreach (['host', 'port'] as $key) {
            if (array_key_exists($key, $patch) && ($settings[$key] ?? null) !== $patch[$key]) {
                $hostPortChanged = true;
            }
        }

        // Merge keys
        foreach ($patch as $k => $v) {
            $settings[$k] = $v;
        }

        writeJson(SETTINGS_FILE, $settings);

        $restartOutput = null;
        if ($hostPortChanged) {
            $restartOutput = restartService();
        }

        ok([
            'message'          => 'Settings updated' . ($hostPortChanged ? ' and server restarted' : ''),
            'restarted'        => $hostPortChanged,
            'restart_output'   => $restartOutput,
        ]);
    }

    err('Method not allowed', 405);
}

// ─── gateways ─────────────────────────────────────────────────────────────────

if ($action === 'gateways') {
    $m = method();

    $settings = file_exists(SETTINGS_FILE) ? readJson(SETTINGS_FILE) : [];
    if (!is_array($settings)) $settings = [];
    $gateways = (isset($settings['gateways']) && is_array($settings['gateways']))
        ? $settings['gateways'] : [];

    // GET — return gateways from settings.json
    if ($m === 'GET') {
        ok($gateways);
    }

    // POST — install a new gateway
    if ($m === 'POST') {
        $b = body();
        $id     = trim((string)($b['id']     ?? ''));
        $name   = trim((string)($b['name']   ?? ''));
        $type   = trim((string)($b['type']   ?? ''));
        $host   = trim((string)($b['host']   ?? ''));
        $active = (int)($b['active'] ?? 1) ? 1 : 0;
        $gwSet  = isset($b['settings']) && is_array($b['settings']) ? $b['settings'] : [];

        if ($id === '')                                              err('Missing id');
        if (!in_array($type, ['tun2socks', 'wireguard'], true))     err('Invalid type');

        foreach ($gateways as $g) {
            if (($g['id'] ?? '') === $id) err("Gateway $id already exists", 409);
        }

        try {
            $res = gw_install($type, $host, $gwSet);
        } catch (Throwable $e) {
            err('Install failed: ' . $e->getMessage(), 500);
        }

        $entry = [
            'id'     => $id,
            'name'   => $name !== '' ? $name : ('gw-' . $res['slot']),
            'tun'    => $res['tun'],
            'type'   => $type,
            'active' => $active,
        ];
        $gateways[] = $entry;
        $settings['gateways'] = $gateways;
        writeJson(SETTINGS_FILE, $settings);

        ok([
            'message' => 'Gateway installed',
            'gateway' => $entry,
            'slot'    => $res['slot'],
            'output'  => $res['output'] ?? '',
        ]);
    }

    // DELETE — remove a gateway by id
    if ($m === 'DELETE') {
        $id = trim((string)($_GET['id'] ?? ''));
        if ($id === '') err('Missing ?id parameter');

        $entry = null;
        $keep  = [];
        foreach ($gateways as $g) {
            if (($g['id'] ?? '') === $id) {
                $entry = $g;
            } else {
                $keep[] = $g;
            }
        }
        if ($entry === null) err("Gateway $id not found", 404);

        $type = (string)($entry['type'] ?? '');
        $tun  = (string)($entry['tun']  ?? '');
        $slot = gw_slot_from_tun($tun);
        if ($slot < 0 || $type === '') {
            err('Gateway record missing tun/type', 500);
        }

        try {
            $out = gw_uninstall($type, $slot);
        } catch (Throwable $e) {
            err('Uninstall failed: ' . $e->getMessage(), 500);
        }

        $settings['gateways'] = $keep;
        writeJson(SETTINGS_FILE, $settings);

        ok([
            'message' => 'Gateway removed',
            'gateway' => $entry,
            'output'  => $out,
        ]);
    }

    err('Method not allowed', 405);
}

// ─── logs ─────────────────────────────────────────────────────────────────────

if ($action === 'logs') {
    if (method() !== 'GET') err('Use GET', 405);

    // Date format: YYYYMMDD — default today
    $dateParam = trim($_GET['date'] ?? '');
    if ($dateParam === '') {
        $dateParam = date('Ymd');
    }

    if (!preg_match('/^\d{8}$/', $dateParam)) {
        err('Invalid date format. Use YYYYMMDD (e.g. 20260409)');
    }

    // Optional: specific filenames (without .log extension) passed as files[]
    // Log files are named YYYYMMDD_HHMMSS_UUID.log
    $requestedFiles = $_GET['files'] ?? [];
    if (!is_array($requestedFiles)) $requestedFiles = [$requestedFiles];
    $requestedFiles = array_filter(array_map('trim', $requestedFiles));

    if (!is_dir(LOGS_DIR)) err('Logs directory not found', 404);

    $result = [];

    if (!empty($requestedFiles)) {
        foreach ($requestedFiles as $name) {
            // Strip .log if caller included it
            $name = preg_replace('/\.log$/', '', $name);
            $path = LOGS_DIR . '/' . $name . '.log';
            if (!file_exists($path)) {
                $result[$name . '.log'] = null;
                continue;
            }
            $result[$name . '.log'] = file_get_contents($path);
        }
    } else {
        // Return all log files for the given date
        $pattern = LOGS_DIR . '/' . $dateParam . '*.log';
        foreach (glob($pattern) as $path) {
            $filename = basename($path);
            $result[$filename] = file_get_contents($path);
        }
    }

    ok($result);
}

// ─── statistics ───────────────────────────────────────────────────────────────

if ($action === 'statistics') {
    if (method() !== 'GET') err('Use GET', 405);

    // Date format: YYYY-MM-DD — default today
    $dateParam = trim($_GET['date'] ?? '');
    if ($dateParam === '') {
        $dateParam = date('Y-m-d');
    }

    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $dateParam)) {
        err('Invalid date format. Use YYYY-MM-DD (e.g. 2026-04-09)');
    }

    if (!file_exists(STATISTICS_FILE)) ok([]);

    $all = readJson(STATISTICS_FILE);
    if (!is_array($all)) ok([]);

    $filtered = [];
    foreach ($all as $uuid => $entry) {
        $startedAt = $entry['started_at'] ?? '';
        // started_at is ISO 8601, e.g. "2026-04-09T12:55:24+00:00"
        if (str_starts_with($startedAt, $dateParam)) {
            $filtered[$uuid] = $entry;
        }
    }

    ok($filtered);
}

// ─── Unknown action ───────────────────────────────────────────────────────────

err("Unknown action: '{$action}'", 404);
