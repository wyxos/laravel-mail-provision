<?php

namespace Wyxos\LaravelMailProvision\Support;

use RuntimeException;

final class EnvFile
{
    /**
     * Set/replace multiple keys in an env file.
     *
     * Values must be passed as already-formatted env values (quoted if desired).
     *
     * @param  array<string, string>  $values
     */
    public static function set(string $path, array $values): void
    {
        $eol = PHP_EOL;
        $contents = '';

        if (is_file($path)) {
            $contents = file_get_contents($path);
            if ($contents === false) {
                throw new RuntimeException("Unable to read env file at {$path}.");
            }

            $eol = str_contains($contents, "\r\n") ? "\r\n" : "\n";
        }

        $lines = $contents === '' ? [] : preg_split('/\\r\\n|\\n|\\r/', $contents);
        if (! is_array($lines)) {
            $lines = [];
        }

        foreach ($values as $key => $value) {
            $pattern = '/^'.preg_quote($key, '/').'=.*/';
            $foundIndex = null;
            $newLines = [];

            foreach ($lines as $i => $line) {
                if (preg_match($pattern, $line) === 1) {
                    if ($foundIndex === null) {
                        $foundIndex = $i;
                        $newLines[] = "{$key}={$value}";
                    }

                    // Drop duplicate definitions.
                    continue;
                }

                $newLines[] = $line;
            }

            $lines = $newLines;

            if ($foundIndex === null) {
                $lines[] = "{$key}={$value}";
            }
        }

        $final = implode($eol, $lines);
        if ($final !== '' && ! str_ends_with($final, $eol)) {
            $final .= $eol;
        }

        $dir = dirname($path);
        if (! is_dir($dir)) {
            if (! mkdir($dir, 0777, true) && ! is_dir($dir)) {
                throw new RuntimeException("Unable to create env directory {$dir}.");
            }
        }

        if (file_put_contents($path, $final) === false) {
            throw new RuntimeException("Unable to write env file at {$path}.");
        }
    }
}
