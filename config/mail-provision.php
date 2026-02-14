<?php

return [
    'sparkpost' => [
        // Provisioning uses the SparkPost REST API key (not SMTP).
        // Defaults to SPARKPOST_PROVISIONING_KEY, then SPARKPOST_API_KEY, then MAIL_PASSWORD.
        'provisioning_key' => env('SPARKPOST_PROVISIONING_KEY', env('SPARKPOST_API_KEY', env('MAIL_PASSWORD'))),
        'base_url' => env('SPARKPOST_API_BASE_URL', 'https://api.sparkpost.com'),
        'tracking_cname_target' => env('SPARKPOST_TRACKING_CNAME_TARGET', 'v2.spgo.io'),
        'subaccount' => env('SPARKPOST_SUBACCOUNT'),
    ],
    'cloudflare' => [
        'api_token' => env('CLOUDFLARE_API_TOKEN'),
        'zone_id' => env('CLOUDFLARE_ZONE_ID'),
        'zone_name' => env('CLOUDFLARE_ZONE_NAME'),
        'base_url' => env('CLOUDFLARE_API_BASE_URL', 'https://api.cloudflare.com/client/v4'),
    ],
];
