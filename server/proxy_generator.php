<?php
/**
 * Proxy generator — creates/removes systemd units and configs for
 * inbound proxy interfaces (strans-intun0..255).
 *
 * Supported types:
 *   - wireguard  : kernel tunnel from a proxy server to this main server
 *
 * Traffic flow: Client → Proxy server → WG tunnel (strans-intunN) → server.py → strans-outtunN → Internet
 */

const PX_TUN_PREFIX  = 'strans-intun';
const PX_TUN_MAX     = 256;
const PX_SYSTEMD_DIR = '/etc/systemd/system';
const PX_WG_DIR      = '/etc/wireguard';

function px_tun_name(int $slot): string
{
    return PX_TUN_PREFIX . $slot;
}

function px_table_id(int $slot): int
{
    // Offset by 200 to avoid collision with gateway tables (100+N)
    return 200 + ($slot % 100);
}

function px_wg_conf_path(int $slot): string
{
    return PX_WG_DIR . '/' . px_tun_name($slot) . '.conf';
}

function px_wg_service_name(int $slot): string
{
    return 'wg-quick@' . px_tun_name($slot) . '.service';
}

/**
 * Scans existing wireguard configs to find the smallest free slot in [0, PX_TUN_MAX).
 */
function px_find_free_slot(): int
{
    $used = [];

    foreach (glob(PX_WG_DIR . '/' . PX_TUN_PREFIX . '*.conf') ?: [] as $f) {
        if (preg_match('/' . preg_quote(PX_TUN_PREFIX, '/') . '(\d+)\.conf$/', $f, $m)) {
            $used[(int)$m[1]] = true;
        }
    }

    for ($i = 0; $i < PX_TUN_MAX; $i++) {
        if (!isset($used[$i])) return $i;
    }
    return -1;
}

function px_slot_from_tun(string $tun): int
{
    if (preg_match('/(\d+)$/', $tun, $m)) return (int)$m[1];
    return -1;
}

function px_sh(string $cmd): string
{
    return trim((string)shell_exec($cmd . ' 2>&1'));
}

/**
 * Write content to a root-owned path via sudo tee.
 */
function px_write_file(string $path, string $content, string $mode = '0644'): void
{
    $proc = proc_open(
        'sudo tee ' . escapeshellarg($path),
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes
    );
    if (!is_resource($proc)) {
        throw new RuntimeException("Cannot run sudo tee for $path");
    }
    fwrite($pipes[0], $content);
    fclose($pipes[0]);
    fclose($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    $code = proc_close($proc);
    if ($code !== 0) {
        throw new RuntimeException("sudo tee $path failed (code $code): $err");
    }
    px_sh('sudo chmod ' . escapeshellarg($mode) . ' ' . escapeshellarg($path));
}

// ─── wireguard ────────────────────────────────────────────────────────────────

/**
 * Expected $settings keys:
 *   private_key          - local (this main server) WG private key
 *   peer_public_key      - remote (proxy server) WG public key
 *   endpoint             - (optional) remote "host:port" — omit if peer connects to us
 *   listen_port          - (optional) local listen port — needed when peer connects to us
 *   local_address        - local tunnel IP with mask, e.g. 10.201.0.1/30
 *   allowed_ips          - (optional) default "0.0.0.0/0"
 *   persistent_keepalive - (optional) default 25
 */
function px_build_wireguard_conf(int $slot, array $settings): string
{
    $table = px_table_id($slot);

    $priv    = trim((string)($settings['private_key']          ?? ''));
    $pub     = trim((string)($settings['peer_public_key']      ?? ''));
    $ep      = trim((string)($settings['endpoint']             ?? ''));
    $local   = trim((string)($settings['local_address']        ?? ''));
    $listen  = trim((string)($settings['listen_port']          ?? ''));
    $allowed = trim((string)($settings['allowed_ips']          ?? '0.0.0.0/0'));
    $keep    = (int)    ($settings['persistent_keepalive']     ?? 25);

    foreach (['private_key' => $priv, 'peer_public_key' => $pub, 'local_address' => $local] as $k => $v) {
        if ($v === '') throw new RuntimeException("wireguard: missing $k");
    }

    $ifaceExtra = '';
    if ($listen !== '') {
        $ifaceExtra = "\nListenPort = {$listen}";
    }

    $peerEndpoint = '';
    if ($ep !== '') {
        $peerEndpoint = "\nEndpoint            = {$ep}";
    }

    return <<<CONF
[Interface]
PrivateKey = {$priv}
Address    = {$local}{$ifaceExtra}
Table      = off
PostUp     = ip route replace default dev %i table {$table}
PostDown   = ip route del default dev %i table {$table} 2>/dev/null || true

[Peer]
PublicKey           = {$pub}{$peerEndpoint}
AllowedIPs          = {$allowed}
PersistentKeepalive = {$keep}
CONF;
}

// ─── install / uninstall ──────────────────────────────────────────────────────

/**
 * Installs a proxy: writes config, enables & starts the service.
 * Returns: ['slot' => int, 'tun' => string, 'output' => string]
 */
function px_install(string $type, string $host, array $settings = []): array
{
    if ($type !== 'wireguard') {
        throw new RuntimeException("Unsupported proxy type: $type (only wireguard)");
    }

    $slot = px_find_free_slot();
    if ($slot < 0) {
        throw new RuntimeException('No free proxy slot (0..' . (PX_TUN_MAX - 1) . ')');
    }
    $tun = px_tun_name($slot);

    if (!is_dir(PX_WG_DIR)) {
        @mkdir(PX_WG_DIR, 0700, true);
    }
    $conf = px_build_wireguard_conf($slot, $settings);
    $path = px_wg_conf_path($slot);
    px_write_file($path, $conf, '0600');

    $svc = px_wg_service_name($slot);
    px_sh('sudo systemctl daemon-reload');
    $out = px_sh('sudo systemctl enable --now ' . escapeshellarg($svc));

    return ['slot' => $slot, 'tun' => $tun, 'output' => $out];
}

/**
 * Uninstalls a proxy: stops the service, removes config, cleans the interface.
 * Returns: array of shell outputs for diagnostics.
 */
function px_uninstall(string $type, int $slot): array
{
    $tun = px_tun_name($slot);
    $out = [];

    if ($type !== 'wireguard') {
        throw new RuntimeException("Unknown proxy type: $type");
    }

    $svc = px_wg_service_name($slot);
    $out['stop']    = px_sh('sudo systemctl stop '    . escapeshellarg($svc));
    $out['disable'] = px_sh('sudo systemctl disable ' . escapeshellarg($svc));
    $path = px_wg_conf_path($slot);
    px_sh('sudo rm -f ' . escapeshellarg($path));
    $out['reload'] = px_sh('sudo systemctl daemon-reload');

    // Best-effort interface cleanup
    $out['link_del'] = px_sh('sudo ip link delete ' . escapeshellarg($tun));

    return $out;
}
