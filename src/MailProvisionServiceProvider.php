<?php

namespace Wyxos\LaravelMailProvision;

use Illuminate\Support\ServiceProvider;
use Wyxos\LaravelMailProvision\Console\Commands\ProvisionMailDomainCommand;

class MailProvisionServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/mail-provision.php', 'mail-provision');
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/mail-provision.php' => config_path('mail-provision.php'),
        ], 'mail-provision-config');

        if ($this->app->runningInConsole()) {
            $this->commands([
                ProvisionMailDomainCommand::class,
            ]);
        }
    }
}
