<?php
/**
 * Gateway generator — creates/removes systemd units and configs for
 * outbound gateway interfaces (strans-outtun0..255).
 *
 * Supported types:
 *   - tun2socks  : SOCKS5 upstream, userspace, no ICMP
 *   - wireguard  : kernel tunnel to a peer server, full IP stack
 *
 * All shell commands rely on sudo being configured for the web user.
 * See: SUDOERS snippet documented at the bottom of this file.
 */

const GW_TUN_PREFIX  = 'strans-outtun';
const GW_TUN_MAX     = 256;
const GW_SYSTEMD_DIR = '/etc/systemd/system';
const GW_WG_DIR      = '/etc/wireguard';

function gw_tun_name(int $slot): string
{
    return GW_TUN_PREFIX . $slot;
}

function gw_table_id(int $slot): int
{
    // Matches server.py _tun_table_id: 100 + (N % 100)
    return 100 + ($slot % 100);
}

function gw_tun2socks_unit_path(int $slot): string
{
    return GW_SYSTEMD_DIR . '/tun2socks-' . gw_tun_name($slot) . '.service';
}

function gw_wg_conf_path(int $slot): string
{
    return GW_WG_DIR . '/' . gw_tun_name($slot) . '.conf';
}

function gw_tun2socks_service_name(int $slot): string
{
    return 'tun2socks-' . gw_tun_name($slot) . '.service';
}

function gw_wg_service_name(int $slot): string
{
    return 'wg-quick@' . gw_tun_name($slot) . '.service';
}

/**
 * Scans existing tun2socks units and wireguard configs to find the
 * smallest free slot in [0, GW_TUN_MAX).
 */
function gw_find_free_slot(): int
{
    $used = [];

    foreach (glob(GW_SYSTEMD_DIR . '/tun2socks-' . GW_TUN_PREFIX . '*.service') ?: [] as $f) {
        if (preg_match('/' . preg_quote(GW_TUN_PREFIX, '/') . '(\d+)\.service$/', $f, $m)) {
            $used[(int)$m[1]] = true;
        }
    }
    foreach (glob(GW_WG_DIR . '/' . GW_TUN_PREFIX . '*.conf') ?: [] as $f) {
        if (preg_match('/' . preg_quote(GW_TUN_PREFIX, '/') . '(\d+)\.conf$/', $f, $m)) {
            $used[(int)$m[1]] = true;
        }
    }

    for ($i = 0; $i < GW_TUN_MAX; $i++) {
        if (!isset($used[$i])) return $i;
    }
    return -1;
}

function gw_slot_from_tun(string $tun): int
{
    if (preg_match('/(\d+)$/', $tun, $m)) return (int)$m[1];
    return -1;
}

function gw_sh(string $cmd): string
{
    return trim((string)shell_exec($cmd . ' 2>&1'));
}

// ─── tun2socks ────────────────────────────────────────────────────────────────

function gw_build_tun2socks_unit(int $slot, string $proxyUrl): string
{
    $tun   = gw_tun_name($slot);
    $table = gw_table_id($slot);
    // Point-to-point /30 per slot in 198.18.0.0/16 (не пересекается с 198.19.0.0/24 VPN)
    $octet = $slot;                   // 198.18.<slot>.1/30  →  256 slots умещаются в /16
    $ip    = "198.18.{$octet}.1/30";
    $proxyEsc = escapeshellarg($proxyUrl);

    return <<<UNIT
[Unit]
Description=tun2socks outbound gateway {$tun}
After=network.target

[Service]
Type=simple
ExecStartPre=/bin/sh -c 'ip tuntap add mode tun dev {$tun} 2>/dev/null || true; ip addr add {$ip} dev {$tun} 2>/dev/null || true; ip link set dev {$tun} up; ip route replace default dev {$tun} table {$table}'
ExecStart=/usr/local/bin/tun2socks -device {$tun} -proxy {$proxyEsc}
ExecStopPost=/bin/sh -c 'ip link delete {$tun} 2>/dev/null || true'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT;
}

// ─── wireguard ────────────────────────────────────────────────────────────────

/**
 * Expected $settings keys:
 *   private_key          - local (this main server) WG private key
 *   peer_public_key      - remote (exit server) WG public key
 *   endpoint             - remote "host:port"
 *   local_address        - local tunnel IP with mask, e.g. 10.200.0.2/30
 *   allowed_ips          - (optional) default "0.0.0.0/0"
 *   persistent_keepalive - (optional) default 25
 */
function gw_build_wireguard_conf(int $slot, array $settings): string
{
    $table = gw_table_id($slot);

    $priv    = trim((string)($settings['private_key']          ?? ''));
    $pub     = trim((string)($settings['peer_public_key']      ?? ''));
    $ep      = trim((string)($settings['endpoint']             ?? ''));
    $local   = trim((string)($settings['local_address']        ?? ''));
    $allowed = trim((string)($settings['allowed_ips']          ?? '0.0.0.0/0'));
    $keep    = (int)    ($settings['persistent_keepalive']     ?? 25);

    foreach (['private_key' => $priv, 'peer_public_key' => $pub, 'endpoint' => $ep, 'local_address' => $local] as $k => $v) {
        if ($v === '') throw new RuntimeException("wireguard: missing $k");
    }

    return <<<CONF
[Interface]
PrivateKey = {$priv}
Address    = {$local}
Table      = off
PostUp     = ip route replace default dev %i table {$table}
PostDown   = ip route del default dev %i table {$table} 2>/dev/null || true

[Peer]
PublicKey           = {$pub}
Endpoint            = {$ep}
AllowedIPs          = {$allowed}
PersistentKeepalive = {$keep}
CONF;
}

// ─── install / uninstall ──────────────────────────────────────────────────────

/**
 * Installs a gateway: writes config, enables & starts the service.
 * Returns: ['slot' => int, 'tun' => string, 'output' => string]
 */
function gw_install(string $type, string $host, array $settings = []): array
{
    $slot = gw_find_free_slot();
    if ($slot < 0) {
        throw new RuntimeException('No free gateway slot (0..' . (GW_TUN_MAX - 1) . ')');
    }
    $tun = gw_tun_name($slot);

    if ($type === 'tun2socks') {
        if ($host === '' || !preg_match('#^socks5://#', $host)) {
            throw new RuntimeException('tun2socks host must start with socks5://');
        }
        $unit = gw_build_tun2socks_unit($slot, $host);
        $path = gw_tun2socks_unit_path($slot);
        if (file_put_contents($path, $unit) === false) {
            throw new RuntimeException("Cannot write $path");
        }
        $svc = gw_tun2socks_service_name($slot);
        gw_sh('sudo systemctl daemon-reload');
        $out = gw_sh('sudo systemctl enable --now ' . escapeshellarg($svc));

        return ['slot' => $slot, 'tun' => $tun, 'output' => $out];
    }

    if ($type === 'wireguard') {
        if (!is_dir(GW_WG_DIR)) {
            @mkdir(GW_WG_DIR, 0700, true);
        }
        $conf = gw_build_wireguard_conf($slot, $settings);
        $path = gw_wg_conf_path($slot);
        if (file_put_contents($path, $conf) === false) {
            throw new RuntimeException("Cannot write $path");
        }
        @chmod($path, 0600);

        $svc = gw_wg_service_name($slot);
        gw_sh('sudo systemctl daemon-reload');
        $out = gw_sh('sudo systemctl enable --now ' . escapeshellarg($svc));

        return ['slot' => $slot, 'tun' => $tun, 'output' => $out];
    }

    throw new RuntimeException("Unknown gateway type: $type");
}

/**
 * Uninstalls a gateway: stops the service, removes unit/config, cleans the interface.
 * Returns: array of shell outputs for diagnostics.
 */
function gw_uninstall(string $type, int $slot): array
{
    $tun = gw_tun_name($slot);
    $out = [];

    if ($type === 'tun2socks') {
        $svc = gw_tun2socks_service_name($slot);
        $out['stop']    = gw_sh('sudo systemctl stop '    . escapeshellarg($svc));
        $out['disable'] = gw_sh('sudo systemctl disable ' . escapeshellarg($svc));
        $path = gw_tun2socks_unit_path($slot);
        if (file_exists($path)) @unlink($path);
        $out['reload'] = gw_sh('sudo systemctl daemon-reload');
    } elseif ($type === 'wireguard') {
        $svc = gw_wg_service_name($slot);
        $out['stop']    = gw_sh('sudo systemctl stop '    . escapeshellarg($svc));
        $out['disable'] = gw_sh('sudo systemctl disable ' . escapeshellarg($svc));
        $path = gw_wg_conf_path($slot);
        if (file_exists($path)) @unlink($path);
        $out['reload'] = gw_sh('sudo systemctl daemon-reload');
    } else {
        throw new RuntimeException("Unknown gateway type: $type");
    }

    // Best-effort interface cleanup (no-op if already gone)
    $out['link_del'] = gw_sh('sudo ip link delete ' . escapeshellarg($tun));

    return $out;
}

/*
 * SUDOERS snippet (adjust user/group; here: www-data):
 *
 *   www-data ALL=(root) NOPASSWD: /bin/systemctl daemon-reload, \
 *                                 /bin/systemctl start *, \
 *                                 /bin/systemctl stop *, \
 *                                 /bin/systemctl enable *, \
 *                                 /bin/systemctl disable *, \
 *                                 /bin/systemctl enable --now *, \
 *                                 /sbin/ip link delete *
 *
 * file_put_contents to /etc/systemd/system/ and /etc/wireguard/ requires
 * those directories to be writable by the web user (or use a sudoed writer).
 * Simplest: chown -R www-data:www-data /etc/systemd/system (not recommended)
 * Better:   put files elsewhere and symlink, or run api.php via a wrapper.
 */
