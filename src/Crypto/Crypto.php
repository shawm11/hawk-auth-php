<?php

namespace Shawm11\Hawk\Crypto;

use Shawm11\Hawk\Utils\Utils;

class Crypto implements CryptoInterface
{
    /**
     * MAC normalization format version. Prevents comparison of MAC values
     * generated with different normalized string formats.
     *
     * @var string
     */
    protected $headerVersion = '1';

    /**
     * Supported HMAC algorithms
     *
     * @var array
     */
    public $algorithms = ['sha1', 'sha256'];


    public function calculateMac($type, $credentials, $options)
    {
        $normalized = $this->generateNormalizedString($type, $options);
        $hmac = hash_hmac($credentials['algorithm'], $normalized, $credentials['key'], true);
        $digest = base64_encode($hmac);

        return $digest;
    }

    public function generateNormalizedString($type, $options)
    {
        /*
         * Get resource URL
         */

        $resource = empty($options['resource'])
            ? ''
            : $options['resource'];

        if ($resource && $resource[0] !== '/') {
            $url = parse_url($resource);
            $resource = (empty($url['path']) ? '' : $url['path'])
                      . (empty($url['query']) ? '' : ('?' . $url['query']));
        }

        /*
         * Construct normalized string
         */

        $normalized = "hawk.{$this->headerVersion}.$type\n"
                    . "{$options['ts']}\n"
                    . "{$options['nonce']}\n"
                    . strtoupper(empty($options['method']) ? '' : $options['method']) . "\n"
                    . "$resource\n"
                    . strtolower($options['host']) . "\n"
                    . "{$options['port']}\n"
                    . (empty($options['hash']) ? '' : $options['hash']) . "\n";

        if (!empty($options['ext'])) {
            $normalized .= str_replace("\n", '\n', str_replace('\\', '\\\\', $options['ext']));
        }

        $normalized .= "\n";

        if (!empty($options['app'])) {
            $normalized .= "{$options['app']}\n"
                        . (empty($options['dlg']) ? '' : $options['dlg']) . "\n";
        }

        return $normalized;
    }

    public function calculatePayloadHash($payload, $algorithm, $contentType = null)
    {
        $data = "hawk.{$this->headerVersion}.payload\n"
              . (new Utils)->parseContentType($contentType) . "\n"
              . ($payload ? $payload : '') . "\n";
        $hash = hash($algorithm, $data, true);

        return base64_encode($hash);
    }

    public function calculateTsMac($ts, $credentials)
    {
        $hmac = hash_hmac(
            $credentials['algorithm'],
            // If $ts is a float with a ".0" at the end, the ".0" is supposed to
            // be automatically truncated when the float is converted to a
            // string.
            "hawk.{$this->headerVersion}.ts\n$ts\n",
            $credentials['key'],
            true
        );

        return base64_encode($hmac);
    }

    public function timestampMessage($credentials, $localtimeOffsetMsec = 0.0)
    {
        $now = (new Utils)->nowSecs($localtimeOffsetMsec);
        $tsm = $this->calculateTsMac($now, $credentials);

        return [
            'ts' => $now,
            'tsm' => $tsm
        ];
    }
}
