<?php

namespace Shawm11\Hawk\Crypto;

use Shawm11\Hawk\Utils\Utils;

class Crypto
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
    public $algorithims = ['sha1', 'sha256'];


    public function calculateMac($type, $credentials, $options)
    {
        $normalized = $this->generateNormalizedString($type, $options);
        $hmac = hash_hmac($credentials['algorithm'], $normalized, $credentials['key']);
        $digest = base64_encode($hmac);

        return $digest;
    }

    public function generateNormalizedString($type, $options)
    {
        /*
         * Get resource URL
         */

        $resource = (isset($options['resource']) && $options['resource'])
            ? $options['resource']
            : '';

        if ($resource && $resource[0] !== '/') {
            $url = parse_url($resource);
            $resource = $uri['path'] . (isset($uri['query']) && $uri['query']) ? ('?'. $uri['query']) : '';
        }

        /*
         * Construct normalized string
         */

        $normalized = "hawk.{$this->headerVersion}.$type\n"
                    . "{$options['ts']}\n"
                    . "{$options['nonce']}\n"
                    . strtoupper((isset($options['method']) && $options['method']) ? $options['method'] : '') . "\n"
                    . "$resource\n"
                    . mb_strtolower($options['host']) . "\n"
                    . "{$options['port']}\n"
                    . ((isset($options['hash']) && $options['hash']) ? $options['hash'] : '') . "\n";

        if (isset($options['ext']) && $options['ext']) {
            $normalized .= str_replace('\\', '\\\\', str_replace("\n", '\n', $options['ext']));
        }

        $normalized .= "\n";

        if (isset($options['app']) && $options['app']) {
            $normalized .= "{$options['app']}\n"
                        . ((isset($options['dlg']) && $options['dlg']) ? $options['dlg'] : '') . "\n";
        }

        return $normalized;
    }

    public function calculatePayloadHash($payload, $algorithm, $contentType)
    {
        $data = "hawk.{$this->headerVersion}.payload\n"
              . (new Utils)->parseContentType($contentType) . "\n"
              . ($payload ? $payload : '') . "\n";
        $hash = hash($algorithm, $data);

        return base64_encode($hash);
    }

    public function calculateTsMac($ts, $credentials)
    {
        $hmac = hash_hmac($credentials['algorithm'], "hawk.{$this->headerVersion}.ts\n$ts\n", $credentials['key']);

        return base64_encode($hmac);
    }

    public function timestampMessage($credentials, $localtimeOffsetMsec)
    {
        $now = (new Utils)->nowSecs($localtimeOffsetMsec);
        $tsm = $this->calculateTsMac($now, $credentials);

        return [
            'ts' => $now,
            'tsm' => $tsm
        ];
    }
}
