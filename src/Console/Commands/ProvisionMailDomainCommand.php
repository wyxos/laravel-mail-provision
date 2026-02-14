<?php

namespace Wyxos\LaravelMailProvision\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use RuntimeException;
use Throwable;
use Wyxos\LaravelMailProvision\Support\EnvFile;

class ProvisionMailDomainCommand extends Command
{
    protected $signature = 'mail:provision-domain
        {domain? : Sending domain (defaults to APP_DOMAIN or APP_URL host)}
        {--tracking= : Tracking domain (defaults to sp.<domain>)}
        {--spf= : SPF TXT value (defaults to "v=spf1 include:_spf.sparkpostmail.com ~all")}
        {--dmarc= : DMARC TXT value (defaults to "v=DMARC1; p=none; adkim=r; aspf=r; pct=100")}
        {--api-key= : SparkPost API key (will be written to MAIL_PASSWORD if configuring env)}
        {--no-env : Do not write SparkPost SMTP + APP_DOMAIN settings into the env file}
        {--env-file= : Env file path to update (defaults to the current environment file)}
        {--skip-spf : Skip SPF TXT provisioning}
        {--skip-dmarc : Skip DMARC TXT provisioning}
        {--timeout=900 : Max seconds to poll verification}
        {--interval=15 : Poll interval in seconds}';

    protected $description = 'Provision SparkPost + Cloudflare records for a sending domain and verify it';

    private ?string $resolvedZoneId = null;

    private ?string $currentDomain = null;

    private ?string $sparkPostProvisioningKey = null;

    public function handle(): int
    {
        try {
            $domain = $this->resolveDomain();
            $trackingDomain = $this->resolveTrackingDomain($domain);
            $timeout = max(0, (int) $this->option('timeout'));
            $interval = max(0, (int) $this->option('interval'));
            $this->currentDomain = $domain;
            $spfValue = $this->resolveSpfValue();
            $dmarcValue = $this->resolveDmarcValue();

            $apiKey = $this->resolveSparkPostApiKeyForProvisioning();

            if (! (bool) $this->option('no-env')) {
                $this->configureEnv(
                    domain: $domain,
                    apiKey: $apiKey,
                    envPath: $this->resolveEnvFilePath(),
                );
            }

            $this->line("Sending domain: {$domain}");
            $this->line("Tracking domain: {$trackingDomain}");

            $this->ensureTrackingDomain($trackingDomain);
            $this->ensureSendingDomain($domain);

            $dkimRecord = $this->resolveDkimRecord($domain);
            $trackingTarget = (string) config('mail-provision.sparkpost.tracking_cname_target', 'v2.spgo.io');

            $this->ensureCloudflareRecord(
                name: $trackingDomain,
                type: 'CNAME',
                content: $trackingTarget,
                proxied: false,
            );

            $this->ensureCloudflareRecord(
                name: $dkimRecord['name'],
                type: 'TXT',
                content: $dkimRecord['value'],
            );

            if (! (bool) $this->option('skip-spf')) {
                $this->ensureCloudflarePolicyRecord(
                    name: $domain,
                    desiredContent: $spfValue,
                    prefix: 'v=spf1',
                    label: 'SPF',
                );
            }

            if (! (bool) $this->option('skip-dmarc')) {
                $this->ensureCloudflarePolicyRecord(
                    name: "_dmarc.{$domain}",
                    desiredContent: $dmarcValue,
                    prefix: 'v=dmarc1',
                    label: 'DMARC',
                );
            }

            if (! $this->pollTrackingVerification($trackingDomain, $timeout, $interval)) {
                $this->error('Timed out waiting for SparkPost tracking domain verification.');

                return self::FAILURE;
            }

            $this->ensureSendingTrackingDomain($domain, $trackingDomain);

            if (! $this->pollVerification($domain, $trackingDomain, $timeout, $interval)) {
                $this->error('Timed out waiting for SparkPost verification to complete.');

                return self::FAILURE;
            }

            $this->info('Mail domain provisioning completed successfully.');

            return self::SUCCESS;
        } catch (Throwable $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }
    }

    private function resolveEnvFilePath(): string
    {
        $path = trim((string) ($this->option('env-file') ?? ''));

        return $path !== '' ? $path : app()->environmentFilePath();
    }

    private function configureEnv(string $domain, string $apiKey, string $envPath): void
    {
        $desiredAppDomain = $this->normalizeDomain($domain);

        EnvFile::set($envPath, [
            'APP_DOMAIN' => $desiredAppDomain,
            'MAIL_MAILER' => 'smtp',
            'MAIL_HOST' => 'smtp.sparkpostmail.com',
            'MAIL_PORT' => '587',
            'MAIL_USERNAME' => 'SMTP_Injection',
            'MAIL_PASSWORD' => $apiKey,
            'MAIL_ENCRYPTION' => 'tls',
            // phpdotenv supports variable expansion with ${...}
            'MAIL_FROM_ADDRESS' => 'no-reply@${APP_DOMAIN}',
            'MAIL_FROM_NAME' => '"${APP_NAME}"',
        ]);

        $this->line("Updated env file: {$envPath}");
    }

    private function resolveDomain(): string
    {
        $candidate = (string) ($this->argument('domain') ?? '');
        if ($candidate !== '') {
            return $this->normalizeDomain($candidate);
        }

        $candidate = (string) config('app.domain', '');
        if ($candidate !== '') {
            return $this->normalizeDomain($candidate);
        }

        $host = (string) parse_url((string) config('app.url', ''), PHP_URL_HOST);
        if ($host !== '') {
            return $this->normalizeDomain($host);
        }

        throw new RuntimeException('No domain provided. Pass {domain} or set APP_DOMAIN / APP_URL.');
    }

    private function resolveTrackingDomain(string $domain): string
    {
        $candidate = (string) ($this->option('tracking') ?? '');

        return $this->normalizeDomain($candidate !== '' ? $candidate : "sp.{$domain}");
    }

    private function normalizeDomain(string $domain): string
    {
        return Str::lower(trim($domain, ". \t\n\r\0\x0B"));
    }

    private function resolveSpfValue(): string
    {
        $value = trim((string) ($this->option('spf') ?? ''));
        if ($value === '') {
            $value = 'v=spf1 include:_spf.sparkpostmail.com ~all';
        }

        if (! Str::startsWith(Str::lower($value), 'v=spf1')) {
            throw new RuntimeException('Invalid SPF value. It must start with "v=spf1".');
        }

        return $value;
    }

    private function resolveDmarcValue(): string
    {
        $value = trim((string) ($this->option('dmarc') ?? ''));
        if ($value === '') {
            $value = 'v=DMARC1; p=none; adkim=r; aspf=r; pct=100';
        }

        if (! Str::startsWith(Str::lower($value), 'v=dmarc1')) {
            throw new RuntimeException('Invalid DMARC value. It must start with "v=DMARC1".');
        }

        return $value;
    }

    private function resolveSparkPostApiKeyForProvisioning(): string
    {
        if ($this->sparkPostProvisioningKey !== null && $this->sparkPostProvisioningKey !== '') {
            return $this->sparkPostProvisioningKey;
        }

        $candidate = trim((string) ($this->option('api-key') ?? ''));
        if ($candidate !== '') {
            return $this->sparkPostProvisioningKey = $candidate;
        }

        $candidate = (string) config('mail-provision.sparkpost.provisioning_key', '');
        if ($candidate !== '') {
            return $this->sparkPostProvisioningKey = $candidate;
        }

        if ($this->input->isInteractive()) {
            $entered = (string) $this->secret('SparkPost API key (will be stored in MAIL_PASSWORD)');
            $entered = trim($entered);
            if ($entered !== '') {
                return $this->sparkPostProvisioningKey = $entered;
            }
        }

        throw new RuntimeException('Missing SparkPost API key. Pass --api-key or set SPARKPOST_API_KEY / MAIL_PASSWORD.');
    }

    private function ensureTrackingDomain(string $trackingDomain): void
    {
        $encodedDomain = rawurlencode($trackingDomain);

        $existing = $this->sparkPostClient()->get("api/v1/tracking-domains/{$encodedDomain}");
        if ($existing->status() !== 404) {
            $this->ensureSparkPostSuccess($existing, "Failed loading tracking domain {$trackingDomain}");
            $this->line("Tracking domain already exists: {$trackingDomain}");

            return;
        }

        $create = $this->sparkPostClient()->post('api/v1/tracking-domains', [
            'domain' => $trackingDomain,
        ]);

        if ($create->status() === 409) {
            $this->line("Tracking domain already exists: {$trackingDomain}");

            return;
        }

        $this->ensureSparkPostSuccess($create, "Failed creating tracking domain {$trackingDomain}");
        $this->info("Created tracking domain: {$trackingDomain}");
    }

    private function ensureSendingDomain(string $domain): void
    {
        $encodedDomain = rawurlencode($domain);
        $existing = $this->sparkPostClient()->get("api/v1/sending-domains/{$encodedDomain}");

        if ($existing->status() === 404) {
            $create = $this->sparkPostClient()->post('api/v1/sending-domains', [
                'domain' => $domain,
            ]);

            if ($create->status() === 409) {
                $this->line("Sending domain already exists: {$domain}");

                return;
            }

            $this->ensureSparkPostSuccess($create, "Failed creating sending domain {$domain}");
            $this->info("Created sending domain: {$domain}");

            return;
        }

        $this->ensureSparkPostSuccess($existing, "Failed loading sending domain {$domain}");
        $this->line("Sending domain already exists: {$domain}");
    }

    private function ensureSendingTrackingDomain(string $domain, string $trackingDomain): void
    {
        $encodedDomain = rawurlencode($domain);
        $existing = $this->sparkPostClient()->get("api/v1/sending-domains/{$encodedDomain}");
        $this->ensureSparkPostSuccess($existing, "Failed loading sending domain {$domain}");

        $existingTrackingDomain = (string) data_get($existing->json(), 'results.tracking_domain', '');
        if ($existingTrackingDomain !== '' && $this->normalizeDomain($existingTrackingDomain) === $trackingDomain) {
            $this->line("Sending domain already bound to tracking domain: {$trackingDomain}");

            return;
        }

        $update = $this->sparkPostClient()->put("api/v1/sending-domains/{$encodedDomain}", [
            'tracking_domain' => $trackingDomain,
        ]);
        $this->ensureSparkPostSuccess($update, "Failed updating sending domain {$domain}");
        $this->info("Bound sending domain to tracking domain: {$domain} -> {$trackingDomain}");
    }

    private function pollTrackingVerification(string $trackingDomain, int $timeoutSeconds, int $intervalSeconds): bool
    {
        $deadline = microtime(true) + $timeoutSeconds;
        $attempt = 1;

        do {
            $trackingStatus = $this->verifyTrackingDomain($trackingDomain);
            $this->line(sprintf(
                'Tracking verify attempt %d: cname_status=%s',
                $attempt,
                $trackingStatus['cname_status'] ?: 'unknown',
            ));

            if ($trackingStatus['verified']) {
                return true;
            }

            if (microtime(true) >= $deadline) {
                return false;
            }

            if ($intervalSeconds > 0) {
                sleep($intervalSeconds);
            }

            $attempt++;
        } while (true);
    }

    /**
     * @return array{name: string, value: string}
     */
    private function resolveDkimRecord(string $domain): array
    {
        $encodedDomain = rawurlencode($domain);
        $response = $this->sparkPostClient()->get("api/v1/sending-domains/{$encodedDomain}/dkim-keys/default");
        $this->ensureSparkPostSuccess($response, "Failed loading DKIM key for {$domain}");

        $results = (array) data_get($response->json(), 'results', []);
        $record = (string) data_get($results, 'dns.dkim_record', '');
        $value = (string) data_get($results, 'dns.dkim_value', '');

        if ($record !== '' && $value !== '') {
            return [
                'name' => $this->normalizeDomain($record),
                'value' => $value,
            ];
        }

        $selector = (string) data_get($results, 'selector', '');
        $publicKey = (string) data_get($results, 'public', '');

        if ($selector === '' || $publicKey === '') {
            throw new RuntimeException("SparkPost did not return usable DKIM DNS values for {$domain}.");
        }

        return [
            'name' => "{$this->normalizeDomain($selector)}._domainkey.{$domain}",
            'value' => "v=DKIM1; k=rsa; p={$publicKey}",
        ];
    }

    private function ensureCloudflareRecord(string $name, string $type, string $content, ?bool $proxied = null): void
    {
        $zoneId = $this->resolveCloudflareZoneId();
        $normalizedName = $this->normalizeDomain($name);
        $normalizedType = Str::upper($type);

        $find = $this->cloudflareClient()->get("zones/{$zoneId}/dns_records", [
            'type' => $normalizedType,
            'name' => $normalizedName,
            'per_page' => 100,
        ]);

        $findPayload = $this->ensureCloudflareSuccess($find, "Failed checking Cloudflare {$normalizedType} {$normalizedName}");
        $existing = (array) data_get($findPayload, 'result.0', []);

        $body = [
            'type' => $normalizedType,
            'name' => $normalizedName,
            'content' => $content,
            'ttl' => 1,
        ];

        if ($proxied !== null && $normalizedType === 'CNAME') {
            $body['proxied'] = $proxied;
        }

        if ($existing !== []) {
            $existingContent = (string) ($existing['content'] ?? '');
            $existingProxied = (bool) ($existing['proxied'] ?? false);
            $sameProxied = $proxied === null || $existingProxied === $proxied || $normalizedType !== 'CNAME';

            if ($existingContent === $content && $sameProxied) {
                $this->line("Cloudflare {$normalizedType} up-to-date: {$normalizedName}");

                return;
            }

            $recordId = (string) ($existing['id'] ?? '');
            if ($recordId === '') {
                throw new RuntimeException("Cloudflare returned {$normalizedType} record without an id for {$normalizedName}.");
            }

            $update = $this->cloudflareClient()->put("zones/{$zoneId}/dns_records/{$recordId}", $body);
            $this->ensureCloudflareSuccess($update, "Failed updating Cloudflare {$normalizedType} {$normalizedName}");
            $this->info("Updated Cloudflare {$normalizedType}: {$normalizedName}");

            return;
        }

        $create = $this->cloudflareClient()->post("zones/{$zoneId}/dns_records", $body);
        $this->ensureCloudflareSuccess($create, "Failed creating Cloudflare {$normalizedType} {$normalizedName}");
        $this->info("Created Cloudflare {$normalizedType}: {$normalizedName}");
    }

    private function ensureCloudflarePolicyRecord(string $name, string $desiredContent, string $prefix, string $label): void
    {
        $zoneId = $this->resolveCloudflareZoneId();
        $normalizedName = $this->normalizeDomain($name);
        $normalizedPrefix = Str::lower($prefix);

        $find = $this->cloudflareClient()->get("zones/{$zoneId}/dns_records", [
            'type' => 'TXT',
            'name' => $normalizedName,
            'per_page' => 100,
        ]);
        $payload = $this->ensureCloudflareSuccess($find, "Failed checking Cloudflare TXT {$normalizedName}");
        $records = array_values(array_filter((array) data_get($payload, 'result', []), function (mixed $record) use ($normalizedPrefix) {
            $content = Str::lower((string) data_get($record, 'content', ''));

            return Str::startsWith($content, $normalizedPrefix);
        }));

        if (count($records) > 1) {
            throw new RuntimeException("Multiple {$label} TXT records found for {$normalizedName}; please clean up duplicates.");
        }

        if (count($records) === 1) {
            $record = $records[0];
            $existingContent = (string) data_get($record, 'content', '');
            if ($existingContent === $desiredContent) {
                $this->line("Cloudflare {$label} TXT up-to-date: {$normalizedName}");

                return;
            }

            $recordId = (string) data_get($record, 'id', '');
            if ($recordId === '') {
                throw new RuntimeException("Cloudflare returned {$label} TXT without an id for {$normalizedName}.");
            }

            $update = $this->cloudflareClient()->put("zones/{$zoneId}/dns_records/{$recordId}", [
                'type' => 'TXT',
                'name' => $normalizedName,
                'content' => $desiredContent,
                'ttl' => 1,
            ]);
            $this->ensureCloudflareSuccess($update, "Failed updating Cloudflare {$label} TXT {$normalizedName}");
            $this->info("Updated Cloudflare {$label} TXT: {$normalizedName}");

            return;
        }

        $create = $this->cloudflareClient()->post("zones/{$zoneId}/dns_records", [
            'type' => 'TXT',
            'name' => $normalizedName,
            'content' => $desiredContent,
            'ttl' => 1,
        ]);
        $this->ensureCloudflareSuccess($create, "Failed creating Cloudflare {$label} TXT {$normalizedName}");
        $this->info("Created Cloudflare {$label} TXT: {$normalizedName}");
    }

    private function pollVerification(string $domain, string $trackingDomain, int $timeoutSeconds, int $intervalSeconds): bool
    {
        $deadline = microtime(true) + $timeoutSeconds;
        $attempt = 1;

        do {
            $trackingStatus = $this->verifyTrackingDomain($trackingDomain);
            $sendingStatus = $this->verifySendingDomain($domain);

            $this->line(sprintf(
                'Attempt %d: tracking=%s, dkim=%s, ownership=%s, compliance=%s',
                $attempt,
                $trackingStatus['cname_status'] ?: 'unknown',
                $sendingStatus['dkim_status'] ?: 'unknown',
                $sendingStatus['ownership_verified'] ? 'true' : 'false',
                $sendingStatus['compliance_status'] ?: 'unknown',
            ));

            if ($trackingStatus['verified'] && $sendingStatus['verified']) {
                return true;
            }

            if (microtime(true) >= $deadline) {
                return false;
            }

            if ($intervalSeconds > 0) {
                sleep($intervalSeconds);
            }

            $attempt++;
        } while (true);
    }

    /**
     * @return array{verified: bool, cname_status: string}
     */
    private function verifyTrackingDomain(string $trackingDomain): array
    {
        $encodedDomain = rawurlencode($trackingDomain);
        $response = $this->sparkPostClient()->post("api/v1/tracking-domains/{$encodedDomain}/verify");

        if (! $response->successful()) {
            if ($this->isRetryableVerificationError($response)) {
                return [
                    'verified' => false,
                    'cname_status' => $this->extractSparkPostErrorMessage($response) ?: 'pending',
                ];
            }

            $this->ensureSparkPostSuccess($response, "Failed verifying tracking domain {$trackingDomain}");
        }

        $results = (array) data_get($response->json(), 'results', []);
        $cnameStatus = (string) data_get($results, 'cname_status', '');
        $verified = (bool) data_get($results, 'verified', false) || Str::lower($cnameStatus) === 'valid';

        return [
            'verified' => $verified,
            'cname_status' => $cnameStatus,
        ];
    }

    /**
     * @return array{verified: bool, dkim_status: string, ownership_verified: bool, compliance_status: string}
     */
    private function verifySendingDomain(string $domain): array
    {
        $encodedDomain = rawurlencode($domain);
        $response = $this->sparkPostClient()->post("api/v1/sending-domains/{$encodedDomain}/verify", [
            'dkim_verify' => true,
        ]);

        if (! $response->successful()) {
            if ($this->isRetryableVerificationError($response)) {
                return [
                    'verified' => false,
                    'dkim_status' => 'pending',
                    'ownership_verified' => false,
                    'compliance_status' => 'pending',
                ];
            }

            $this->ensureSparkPostSuccess($response, "Failed verifying sending domain {$domain}");
        }

        $results = (array) data_get($response->json(), 'results', []);
        $dkimStatus = $this->extractSendingStatus($results, 'dkim_status');
        $complianceStatus = $this->extractSendingStatus($results, 'compliance_status');
        $ownershipVerified = filter_var(
            $this->extractSendingStatus($results, 'ownership_verified'),
            FILTER_VALIDATE_BOOL
        ) ?: false;

        return [
            'verified' => Str::lower($dkimStatus) === 'valid' && $ownershipVerified,
            'dkim_status' => $dkimStatus,
            'ownership_verified' => $ownershipVerified,
            'compliance_status' => $complianceStatus,
        ];
    }

    private function extractSendingStatus(array $results, string $key): string
    {
        $value = data_get($results, $key);
        if ($value === null) {
            $value = data_get($results, "status.{$key}");
        }

        return is_bool($value) ? ($value ? 'true' : 'false') : (string) ($value ?? '');
    }

    private function sparkPostClient(): PendingRequest
    {
        $apiKey = $this->resolveSparkPostApiKeyForProvisioning();

        $baseUrl = rtrim((string) config('mail-provision.sparkpost.base_url', 'https://api.sparkpost.com'), '/');
        $request = Http::baseUrl($baseUrl)
            ->acceptJson()
            ->asJson()
            ->withHeaders([
                'Authorization' => $apiKey,
            ]);

        $subaccount = (string) config('mail-provision.sparkpost.subaccount', '');

        if ($subaccount !== '') {
            $request = $request->withHeaders([
                'X-MSYS-SUBACCOUNT' => $subaccount,
            ]);
        }

        return $request;
    }

    private function cloudflareClient(): PendingRequest
    {
        $apiToken = (string) config('mail-provision.cloudflare.api_token', '');
        if ($apiToken === '') {
            throw new RuntimeException('Missing Cloudflare API token. Set CLOUDFLARE_API_TOKEN.');
        }

        $baseUrl = rtrim(
            (string) config('mail-provision.cloudflare.base_url', 'https://api.cloudflare.com/client/v4'),
            '/'
        );

        return Http::baseUrl($baseUrl)
            ->acceptJson()
            ->asJson()
            ->withToken($apiToken);
    }

    private function resolveCloudflareZoneId(): string
    {
        if ($this->resolvedZoneId !== null) {
            return $this->resolvedZoneId;
        }

        $zoneId = (string) config('mail-provision.cloudflare.zone_id', '');
        if ($zoneId !== '') {
            return $this->resolvedZoneId = $zoneId;
        }

        $zoneName = (string) config('mail-provision.cloudflare.zone_name', '');
        if ($zoneName === '') {
            if ($this->currentDomain === null) {
                throw new RuntimeException('Cannot infer Cloudflare zone without a domain.');
            }

            $zoneName = $this->inferZoneName($this->currentDomain);
        }

        $response = $this->cloudflareClient()->get('zones', [
            'name' => $zoneName,
            'status' => 'active',
            'per_page' => 1,
        ]);

        $payload = $this->ensureCloudflareSuccess($response, "Failed finding Cloudflare zone {$zoneName}");
        $resolvedZoneId = (string) data_get($payload, 'result.0.id', '');

        if ($resolvedZoneId === '') {
            throw new RuntimeException("Cloudflare zone not found for {$zoneName}. Set CLOUDFLARE_ZONE_ID.");
        }

        return $this->resolvedZoneId = $resolvedZoneId;
    }

    private function inferZoneName(string $domain): string
    {
        $parts = explode('.', $domain);
        $count = count($parts);

        if ($count < 2) {
            throw new RuntimeException(
                "Unable to infer Cloudflare zone from {$domain}. Set CLOUDFLARE_ZONE_NAME or CLOUDFLARE_ZONE_ID."
            );
        }

        return implode('.', array_slice($parts, -2));
    }

    private function ensureSparkPostSuccess(Response $response, string $context): void
    {
        if ($response->successful()) {
            return;
        }

        $message = (string) data_get($response->json(), 'errors.0.message', '');
        if ($message === '') {
            $message = $response->body();
        }

        throw new RuntimeException("{$context}. [{$response->status()}] {$message}");
    }

    /**
     * @return array<string, mixed>
     */
    private function ensureCloudflareSuccess(Response $response, string $context): array
    {
        if (! $response->successful()) {
            throw new RuntimeException("{$context}. [{$response->status()}] {$response->body()}");
        }

        $payload = $response->json();
        if (! is_array($payload)) {
            throw new RuntimeException("{$context}. Cloudflare returned an invalid payload.");
        }

        if (($payload['success'] ?? false) === true) {
            return $payload;
        }

        $message = (string) data_get($payload, 'errors.0.message', '');
        if ($message === '') {
            $message = json_encode($payload, JSON_UNESCAPED_SLASHES) ?: 'Unknown Cloudflare error';
        }

        throw new RuntimeException("{$context}. {$message}");
    }

    private function isRetryableVerificationError(Response $response): bool
    {
        if (! in_array($response->status(), [400, 404, 409, 422], true)) {
            return false;
        }

        $message = Str::lower($this->extractSparkPostErrorMessage($response));

        return Str::contains($message, [
            'not been verified',
            'invalid',
            'verify',
            'dns',
        ]);
    }

    private function extractSparkPostErrorMessage(Response $response): string
    {
        $message = (string) data_get($response->json(), 'errors.0.description', '');
        if ($message !== '') {
            return $message;
        }

        $message = (string) data_get($response->json(), 'errors.0.message', '');
        if ($message !== '') {
            return $message;
        }

        return '';
    }
}
