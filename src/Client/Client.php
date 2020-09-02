<?php

namespace Shawm11\Hawk\Client;

use Shawm11\Hawk\Crypto\Crypto;
use Shawm11\Hawk\Utils\Utils;

class Client implements ClientInterface
{
    /** @var Crypto */
    protected $Crypto;
    /** @var Utils */
    protected $Utils;

    public function __construct()
    {
        $this->Crypto = new Crypto;
        $this->Utils = new Utils;
    }

    /**
     * {@inheritdoc}
     */
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

        $timestamp = empty($options['timestamp'])
            ? $this->Utils->nowSecs(isset($options['localtimeOffsetMsec']) ? $options['localtimeOffsetMsec'] : 0)
            : $options['timestamp'];

        /*
         * Validate credentials
         */

        $credentials = empty($options['credentials'])
            ? null
            : $options['credentials'];

        if (!$credentials ||
            empty($credentials['id']) ||
            empty($credentials['key']) ||
            empty($credentials['algorithm'])
        ) {
            throw new ClientException('Invalid credentials');
        }

        if (in_array($credentials['algorithm'], $this->Crypto->algorithms) === false) {
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
            'nonce' => empty($options['nonce'])
                // Generate random string with 6 characters
                ? substr($this->Utils->base64urlEncode(openssl_random_pseudo_bytes(6)), 0, 6)
                : $options['nonce'],
            'method' => $method,
            'resource' => (empty($uri['path']) ? '' : $uri['path'])
                        . (empty($uri['query']) ? '' : ('?' . $uri['query'])),
            'host' => empty($uri['host']) ? null : $uri['host'],
            'port' => empty($uri['port'])
                ? (isset($uri['scheme']) && $uri['scheme'] === 'https') ? 443 : 80
                : $uri['port'],
            'hash' => empty($options['hash']) ? null : $options['hash'],
            'ext' => empty($options['ext']) ? null : $options['ext'],
            'app' => empty($options['app']) ? null : $options['app'],
            'dlg' => empty($options['dlg']) ? null : $options['dlg']
        ];

        /*
         * Calculate payload hash
         */

        if (!$artifacts['hash'] &&
            (isset($options['payload']) && ($options['payload'] || $options['payload'] === ''))
        ) {
            $artifacts['hash'] = $this->Crypto->calculatePayloadHash(
                isset($options['payload']) ? $options['payload'] : null,
                $credentials['algorithm'],
                isset($options['contentType']) ? $options['contentType'] : null
            );
        }

        $mac = $this->Crypto->calculateMac('header', $credentials, $artifacts);

        /*
         * Construct header
         */
        // Other falsey values allowed
        $hashExt = $artifacts['ext'] && !is_null($artifacts['ext']) && $artifacts['ext'] !== '';
        $header = "Hawk id=\"{$credentials['id']}\", ts=\"{$artifacts['ts']}\", nonce=\"{$artifacts['nonce']}\""
                . ($artifacts['hash'] ? ", hash=\"{$artifacts['hash']}\"" : '')
                . ($hashExt ? ", ext=\"{$this->Utils->escapeHeaderAttribute($artifacts['ext'])}\"" : '')
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

    /**
     * {@inheritdoc}
     */
    public function authenticate($responseHeaders, $credentials, $artifacts, $options = [])
    {
        $result = [];

        // Allow all lowercase header name or proper case header name
        $wwwAuthenticateHeader = isset($responseHeaders['www-authenticate'])
            ? $responseHeaders['www-authenticate']
            : (isset($responseHeaders['WWW-Authenticate']) ? $responseHeaders['WWW-Authenticate'] : null);


        if ($wwwAuthenticateHeader) {
            /*
             * Parse HTTP WWW-Authenticate header
             */

            try {
                $wwwAttributes = $this->Utils->parseAuthorizationHeader($wwwAuthenticateHeader, ['ts', 'tsm', 'error']);
            } catch (\Exception $e) {
                throw new ClientException('Invalid WWW-Authenticate header');
            }

            $result['www-authenticate'] = $wwwAttributes;

            // Validate server timestamp (not used to update clock)
            if (!empty($wwwAttributes['ts'])) {
                $tsm = $this->Crypto->calculateTsMac($wwwAttributes['ts'], $credentials);

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

        if (!$serverAuthorizationHeader && empty($options['required'])) {
            return $result;
        }

        try {
            $serverAuthAttributes = $this->Utils->parseAuthorizationHeader(
                $serverAuthorizationHeader,
                ['mac', 'ext', 'hash']
            );
        } catch (\Exception $e) {
            throw new ClientException('Invalid Server-Authorization header');
        }

        $result['server-authorization'] = $serverAuthAttributes;

        $artifacts['ext'] = isset($serverAuthAttributes['ext'])
            ? $serverAuthAttributes['ext']
            : null;
        $artifacts['hash'] = isset($serverAuthAttributes['hash'])
            ? $serverAuthAttributes['hash']
            : null;

        $mac = $this->Crypto->calculateMac('response', $credentials, $artifacts);

        if ($mac !== $serverAuthAttributes['mac']) {
            throw new ClientException('Bad response MAC');
        }

        if (!isset($options['payload']) ||
           (!$options['payload'] && $options['payload'] !== '')
        ) {
            return $result;
        }

        if (empty($serverAuthAttributes['hash'])) {
            throw new ClientException('Missing response hash attribute');
        }

        $contentTypeHeader = isset($responseHeaders['content-type'])
            ? $responseHeaders['content-type']
            : (isset($responseHeaders['Content-Type']) ? $responseHeaders['Content-Type'] : null);
        $calculatedHash = $this->Crypto->calculatePayloadHash(
            $options['payload'],
            $credentials['algorithm'],
            $contentTypeHeader
        );

        if ($calculatedHash !== $serverAuthAttributes['hash']) {
            throw new ClientException('Bad response payload MAC');
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function getBewit($uri, $options)
    {
        /*
         * Validate inputs
         */

        if (empty($uri) ||
            (gettype($uri) !== 'string' && gettype($uri) !== 'array') ||
            !$options ||
            gettype($options) !== 'array' ||
            empty($options['ttlSec'])
        ) {
            throw new ClientException('Invalid inputs');
        }

        $ext = (!isset($options['ext']) || is_null($options['ext'])) ? '' : $options['ext'];

        /*
         * Get application time before any other processing
         */

        $now = $this->Utils->now(isset($options['localtimeOffsetMsec']) ? $options['localtimeOffsetMsec'] : 0);

        /*
         * Validate credentials
         */

        $credentials = empty($options['credentials'])
            ? null
            : $options['credentials'];

        if (!$credentials ||
            empty($credentials['id']) ||
            empty($credentials['key']) ||
            empty($credentials['algorithm'])
        ) {
            throw new ClientException('Invalid credentials');
        }

        if (in_array($credentials['algorithm'], $this->Crypto->algorithms) === false) {
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

        $exp = floor($now / 1000) + $options['ttlSec'];
        $mac = $this->Crypto->calculateMac('bewit', $credentials, [
            'ts' => $exp,
            'nonce' => '',
            'method' => 'GET',
            'resource' => $uri['path'] . (empty($uri['query']) ? '' : ('?' . $uri['query'])),
            'host' => $uri['host'],
            'port' => empty($uri['port'])
                ? (isset($uri['scheme']) && $uri['scheme'] === 'https') ? 443 : 80
                : $uri['port'],
            'ext' => $ext
        ]);

        /*
         * Construct bewit: id\exp\mac\ext
         */

        $bewit = "{$credentials['id']}\\$exp\\$mac\\$ext";

        return $this->Utils->base64urlEncode($bewit);
    }

    /**
     * {@inheritdoc}
     */
    public function message($host, $port, $message, $options)
    {
        /*
         * Validate inputs
         */

        if (!$host || gettype($host) !== 'string' ||
            !$port || gettype($port) !== 'integer' ||
            is_null($message) || gettype($message) !== 'string' ||
            gettype($options) !== 'array'
        ) {
            throw new ClientException('Invalid inputs');
        }

        /*
         * Get application time before any other processing
         */

        $timestamp = empty($options['timestamp'])
            ? $this->Utils->nowSecs(isset($options['localtimeOffsetMsec']) ? $options['localtimeOffsetMsec'] : 0)
            : $options['timestamp'];

        /*
         * Validate credentials
         */

        $credentials = empty($options['credentials'])
            ? null
            : $options['credentials'];

        if (!$credentials ||
            empty($credentials['id']) ||
            empty($credentials['key']) ||
            empty($credentials['algorithm'])
        ) {
            throw new ClientException('Invalid credentials');
        }

        if (in_array($credentials['algorithm'], $this->Crypto->algorithms) === false) {
            throw new ClientException('Unknown algorithm');
        }

        /*
         * Calculate signature
         */

        $artifacts = [
            'ts' => $timestamp,
            'nonce' => empty($options['nonce'])
                // Generate random string with 6 characters
                ? substr($this->Utils->base64urlEncode(openssl_random_pseudo_bytes(6)), 0, 6)
                : $options['nonce'],
            'host' => $host,
            'port' => $port,
            'hash' => $this->Crypto->calculatePayloadHash($message, $credentials['algorithm'])
        ];

        /*
         * Construct authorization
         */

        $result = [
            'id' => $credentials['id'],
            'ts' => $artifacts['ts'],
            'nonce' => $artifacts['nonce'],
            'hash' => $artifacts['hash'],
            'mac' => $this->Crypto->calculateMac('message', $credentials, $artifacts)
        ];

        return $result;
    }
}
