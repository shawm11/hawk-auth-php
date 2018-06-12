<?php

namespace Shawm11\Hawk\Client;

use Shawm11\Hawk\Crypto\Crypto;
use Shawm11\Hawk\Utils\Utils;

class Client
{
    protected $Crypto;
    protected $Utils;

    public function __construct()
    {
        $Crypto = new Crypto;
        $Utils = new Utils;
    }

    public function header($uri, $method, $options)
    {
        /*
         * Validate inputs
         */

        if (!$uri || (gettype($uri) !== 'string' && gettype($uri) !== 'array') ||
            !$method || gettype($method) !== 'string' ||
            !$options || gettype($options) !== 'array'
        ) {
            throw new ClientException('Invalid argument type');
        }

        /*
         * Get application time before any other processing
         */

        $timestamp = (isset($options['timestamp']) && $options['timestamp'])
            ? $options['timestamp']
            : $Utils->nowSecs($options['localtimeOffsetMsec']);

        /*
         * Validate credentials
         */

        $credentials = (isset($options['credentials']) && $options['credentials'])
            ? $options['credentials']
            : null;

        if (!$credentials ||
            !(isset($credentials['id']) && $credentials['id']) ||
            !(isset($credentials['key']) && $credentials['key']) ||
            !(isset($credentials['algorithm']) && $credentials['algorithm'])
        ) {
            throw new ClientException('Invalid credentials');
        }

        if (in_array($credentials['algorithm'], $Crypto->algorithms) === false) {
            throw new ClientException('Unknown algorithm');
        }

        /*
         * Parse URI
         */

        if (gettype($uri) === 'string') {
            $uri = parse_url($uri);
        }

        /*
         * Calculate signature
         */

        $artifacts = [
            'ts' => $timestamp,
            'nonce' => (isset($options['nonce']) && $options['nonce'])
                ? $options['nonce']
                // Generate random string with 6 characters
                : substr($Utils->base64urlEncode(openssl_random_psuedo_bytes(6)), 0, 6),
            'method' => $method,
            // Maintain trailing '?' when there are no query parameters
            'resource' => $uri['path'] . '?' . (isset($uri['query']) && $uri['query']) ? ($uri['query']) : '',
            'host' => (isset($options['host']) && $options['host']) ? $options['host'] : null,
            'port' => (isset($uri['port']) && $uri['port'])
                ? $uri['port']
                : (isset($uri['scheme']) && $uri['scheme'] === 'https') ? 443 : 80,
            'hash' => (isset($options['hash']) && $options['hash']) ? $options['hash'] : null,
            'ext' => (isset($options['ext']) && $options['ext']) ? $options['ext'] : null,
            'app' => (isset($options['app']) && $options['app']) ? $options['app'] : null,
            'dlg' => (isset($options['dlg']) && $options['dlg']) ? $options['dlg'] : null
        ];

        /*
         * Calculate payload hash
         */

        if (!$artifacts['hash'] &&
            ((isset($options['payload']) && $options['payload']) || $options['payload'] === '')
        ) {
            $artifacts['hash'] = $Crypto->calculatePayloadHash(
                $options['payload'],
                $credentials['algorithm'],
                $options['contentType']
            );
        }

        $mac = $Crypto->calculateMac('header', $credentials, $artifacts);

        /*
         * Construct header
         */

        $hasExt = $artifacts['ext'] !== null && $artifacts['ext'] !== ''; // Other falsey values allowed
        $header = "Hawk id=\"{$credentials['id']}\", ts=\"{$artifacts['ts']}\", nonce=\"{$artifacts['nonce']}\""
                . ($artifacts['hash'] ? ", hash=\"{$artifacts['hash']}\"" : '')
                . ($hashExt ? ", ext=\"{$Utils->escapeHeaderAttribute($artifacts['ext'])}\"" : '')
                . ", mac=\"$mac\"";

        if ($artifacts['app']) {
            $header .= ", app=\"{$artifacts['app']}\""
                    . ($artifacts['dlg'] ? ", dlg=\"{$artifacts['dlg']}\"" : '');
        }

        return [
            'header' => $header,
            'artifacts' => $artifacts
        ];
    }

    public function authenticate($responseHeaders, $credentials, $artifacts, $options = [])
    {
        $result = ['headers' => []];

        // Allow all lowercase header name or proper case header name
        $wwwAuthenticateHeader = isset($responseHeaders['www-authenticate'])
            ? $responseHeaders['www-authenticate']
            : (isset($responseHeaders['WWW-Authenticate']) ? $responseHeaders['WWW-Authenticate'] : null);


        if ($wwwAuthenticateHeader) {
            /*
             * Parse HTTP WWW-Authenticate header
             */

            try {
                $wwwAttributes = $Utils->parseAuthorizationHeader($wwwAuthenticateHeader, ['ts', 'tsm', 'error']);
            } catch (\Exception $e) {
                throw new ClientException('Invalid WWW-Authenticate header');
            }

            $result['headers']['www-authenticate'] = $wwwAttributes;

            // Validate server timestamp (not used to update clock)
            if ($wwwAttributes['ts']) {
                $tsm = $Crypto->calculateTsMac($wwwAttributes['ts'], $credentials);

                if ($tsm !== $wwwAttributes['tsm']) {
                    throw new ClientException('Invalid server timestamp hash');
                }
            }
        }

        /*
         * Parse HTTP Server-Authorization header
         */

        // Allow all lowercase header name or proper case header name
        $serverAuthorizationHeader = isset($responseHeaders['server-authorization'])
            ? $responseHeaders['server-authorization']
            : (isset($responseHeaders['Server-Authorization']) ? $responseHeaders['Server-Authorization'] : null);

        if (!$serverAuthorizationHeader &&
            !(isset($options['required']) && $options['required'])
        ) {
            return $result;
        }

        try {
            $serverAuthAttributes = $Utils->parseAuthorizationHeader(
                $serverAuthorizationHeader,
                ['mac', 'ext', 'hash']
            );
        } catch (\Exception $e) {
            throw new ClientException('Invalid Server-Authorization header');
        }

        $result['server-authorization'] = $serverAuthAttributes;

        $artifacts['ext'] = $serverAuthAttributes['ext'];
        $artifacts['hash'] = $serverAuthAttributes['hash'];

        $mac = $Crypto->calculateMac('response', $credentials, $artifacts);

        if ($mac !== $serverAuthAttributes['mac']) {
            throw new ClientException('Bad response MAC');
        }

        if (!(isset($options['payload']) && $options['payload']) &&
            $options['payload'] !== ''
        ) {
            return $result;
        }

        if (!(isset($serverAuthAttributes['hash']) && $serverAuthAttributes['hash'])) {
            throw new ClientException('Missing response hash attribute');
        }

        $contentTypeHeader = isset($responseHeaders['content-type'])
            ? $responseHeaders['content-type']
            : (isset($responseHeaders['Content-Type']) ? $responseHeaders['Content-Type'] : null);
        $calculatedHash = $Crypto->calculatePayloadHash(
            $options['payload'],
            $credentials['algorithm'],
            $contentTypeHeader
        );

        if ($calculatedHash !== $serverAuthAttributes['hash']) {
            throw new ClientException('Bad response payload MAC');
        }

        return $result;
    }

    public function getBewit($uri, $options)
    {
        /*
         * Validate inputs
         */

        if (!(isset($uri) && $uri) ||
            (gettype($uri) !== 'string' && gettype($uri) !== 'array') ||
            !$options ||
            gettype($options) !== 'array' ||
            !(isset($options['ttlSec']) && $options['ttlSec'])
        ) {
            throw new ClientException('Invalid inputs');
        }

        $ext = (!isset($options['ext']) || $options['ext'] === null) ? '' : $options['ext'];

        /*
         * Get application time before any other processing
         */

        $now = $Utils->now($options['localtimeOffsetMsec']);

        /*
         * Validate credentials
         */

        $credentials = (isset($options['credentials']) && $options['credentials'])
            ? $options['credentials']
            : null;

        if (!$credentials ||
            !(isset($credentials['id']) && $credentials['id']) ||
            !(isset($credentials['key']) && $credentials['key']) ||
            !(isset($credentials['algorithm']) && $credentials['algorithm'])
        ) {
            throw new ClientException('Invalid credentials');
        }

        if (in_array($credentials['algorithm'], $Crypto->algorithms) === false) {
            throw new ClientException('Unknown algorithm');
        }

        /*
         * Parse URI
         */

        if (gettype($uri) !== 'string') {
            $uri = parse_url($uri);
        }

        /*
         * Calculate signature
         */

        $exp = floor($now / 1000) + $options['ttlSec'];
        $mac = $Crypto->calculateMac('bewit', $credentials, [
            'ts' => $exp,
            'nonce' => '',
            'method' => 'GET',
            // Maintain trailing '?' when there are no query parameters
            'resource' => $uri['path'] . '?' . (isset($uri['query']) && $uri['query']) ? ($uri['query']) : '',
            'host' => $uri['host'],
            'port' => (isset($uri['port']) && $uri['port'])
                ? $uri['port']
                : (isset($uri['scheme']) && $uri['scheme'] === 'https') ? 443 : 80,
            'ext' => $ext
        ]);

        /*
         * Construct bewit: idexpmacext
         */

        $bewit = "{$credentials['id']}\\$exp\\$mac\\$ext";

        return $Utils->base64urlEncode($bewit);
    }

    public function message($host, $port, $message, $options = [])
    {
        /*
         * Validate inputs
         */

        if (!$host || gettype($host) !== 'string' ||
            !$port || gettype($port) !== 'integer' ||
            $message === null || gettype($message) !== 'string' ||
            gettype($options) !== 'array'
        ) {
            throw new ClientException('Invalid inputs');
        }

        /*
         * Get application time before any other processing
         */

        $timestamp = (isset($options['timestamp']) && $options['timestamp'])
            ? $options['timestamp']
            : $Utils->nowSecs($options['localtimeOffsetMsec']);

        /*
         * Validate credentials
         */

        $credentials = (isset($options['credentials']) && $options['credentials'])
            ? $options['credentials']
            : null;

        if (!$credentials ||
            !(isset($credentials['id']) && $credentials['id']) ||
            !(isset($credentials['key']) && $credentials['key']) ||
            !(isset($credentials['algorithm']) && $credentials['algorithm'])
        ) {
            throw new ClientException('Invalid credentials');
        }

        if (in_array($credentials['algorithm'], $Crypto->algorithms) === false) {
            throw new ClientException('Unknown algorithm');
        }

        /*
         * Calculate signature
         */

        $artifacts = [
            'ts' => $timestamp,
            'nonce' => (isset($options['nonce']) && $options['nonce'])
                ? $options['nonce']
                // Generate random string with 6 characters
                : substr($Utils->base64urlEncode(openssl_random_psuedo_bytes(6)), 0, 6),
            'host' => $host,
            'port' => $port,
            'hash' => $Crypto->calculatePayloadHash($message, $credentials['algorithm'])
        ];

        /*
         * Construct authorization
         */

        $result = [
            'id' => $credentials['id'],
            'ts' => $artifacts['ts'],
            'nonce' => $artifacts['nonce'],
            'hash' => $artifacts['hash'],
            'mac' => $Crypto->calculateMac('message', $credentials, $artifacts)
        ];

        return $result;
    }
}
