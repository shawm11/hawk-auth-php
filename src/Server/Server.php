<?php

namespace Shawm11\Hawk\Server;

use Shawm11\Hawk\Crypto\Crypto;
use Shawm11\Hawk\Utils\Utils;

class Server implements ServerInterface
{
    /** @var Crypto */
    protected $Crypto;
    /** @var Utils */
    protected $Utils;

    /**
     * RegEx for matching the bewit in the HTTP header
     *
     * @var string
     */
    //                         |--1-||--2--|       |---3--||---4---|
    protected $bewitRegex = '/^(\/.*)([\?&])bewit\=([^&$]*)(?:&(.+))?$/';

    public function __construct()
    {
        $this->Crypto = new Crypto;
        $this->Utils = new Utils;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate($request, callable $credentialsFunc, $options = [])
    {
        /*
         * Default options
         */

        $options['timestampSkewSec'] = empty($options['timestampSkewSec'])
            ? 60
            : $options['timestampSkewSec'];

        /*
         * Get application time before any other processing
         */

        $options['localtimeOffsetMsec'] = isset($options['localtimeOffsetMsec'])
            ? $options['localtimeOffsetMsec']
            : 0;
        $now = $this->Utils->now($options['localtimeOffsetMsec']);

        /*
         * Check host and port
         */

        $host = empty($options['host'])
            ? (empty($request['host']) ? null : $request['host'])
            : $options['host'];
        $port = empty($options['port'])
            ? (empty($request['port']) ? null : $request['port'])
            : $options['port'];

        if (!$host || !$port) {
            throw new BadRequestException('Invalid Host header');
        }

        /*
         * Parse HTTP Authorization header
         */

        $attributes = $this->Utils->parseAuthorizationHeader(
            isset($request['authorization']) ? $request['authorization'] : null
        );

        /*
         * Construct artifacts container
         */

        $artifacts = [
            'method' => empty($request['method']) ? null : $request['method'],
            'host' => $host,
            'port' => $port,
            'resource' => empty($request['url']) ? null : $request['url'],
            'ts' => empty($attributes['ts']) ? null : $attributes['ts'],
            'nonce' => empty($attributes['nonce']) ? null : $attributes['nonce'],
            'hash' => empty($attributes['hash']) ? null : $attributes['hash'],
            'ext' => empty($attributes['ext']) ? null : $attributes['ext'],
            'app' => empty($attributes['app']) ? null : $attributes['app'],
            'dlg' => empty($attributes['dlg']) ? null : $attributes['dlg'],
            'mac' => empty($attributes['mac']) ? null : $attributes['mac'],
            'id' => empty($attributes['id']) ? null : $attributes['id']
        ];

        /*
         * Verify required header attributes
         */

        if (empty($attributes['id']) ||
            empty($attributes['ts']) ||
            empty($attributes['nonce']) ||
            empty($attributes['mac'])
        ) {
            throw new BadRequestException('Missing attributes');
        }

        /*
         * Fetch Hawk credentials
         */

        try {
            $credentials = $credentialsFunc($attributes['id']);
        } catch (\Exception $e) {
            throw new ServerException($e->getMessage(), $e->getCode());
        }

        if (!$credentials) {
            throw new UnauthorizedException('Unknown credentials');
        }

        $result = [
            'credentials' => $credentials,
            'artifacts' => $artifacts
        ];

        if (empty($credentials['key']) || empty($credentials['algorithm'])) {
            throw new ServerException('Invalid credentials');
        }

        if (in_array($credentials['algorithm'], $this->Crypto->algorithms) === false) {
            throw new ServerException('Unknown algorithm');
        }

        /*
         * Calculate MAC
         */

        $mac = $this->Crypto->calculateMac('header', $credentials, $artifacts);

        if (!hash_equals($mac, $attributes['mac'])) {
            throw new UnauthorizedException('Bad MAC');
        }

        /*
         * Check payload hash
         */

        if (isset($options['payload']) &&
            ($options['payload'] || $options['payload'] === '')
        ) {
            if (empty($attributes['hash'])) {
                throw new UnauthorizedException('Missing required payload hash');
            }

            $hash = $this->Crypto->calculatePayloadHash(
                isset($options['payload']) ? $options['payload'] : null,
                $credentials['algorithm'],
                isset($request['contentType']) ? $request['contentType'] : null
            );

            if (!hash_equals($hash, $attributes['hash'])) {
                throw new UnauthorizedException('Bad payload hash');
            }
        }

        /*
         * Check nonce
         */

        if (!empty($options['nonceFunc'])) {
            try {
                $options['nonceFunc']($credentials['key'], $attributes['nonce'], $attributes['ts']);
            } catch (\Exception $e) {
                throw new UnauthorizedException('Invalid nonce');
            }
        }

        /*
         * Check timestamp staleness
         */

        if (abs($attributes['ts'] * 1000 - $now) > ($options['timestampSkewSec'] * 1000)) {
            $tsm = $this->Crypto->timestampMessage($credentials, $options['localtimeOffsetMsec']);
            throw new UnauthorizedException('Stale timestamp', $tsm);
        }

        // If at this point, then authentication was successful

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticatePayload($payload, $credentials, $artifacts, $contentType)
    {
        $calculatedHash = $this->Crypto->calculatePayloadHash($payload, $credentials['algorithm'], $contentType);

        if (!hash_equals($calculatedHash, $artifacts['hash'])) {
            throw new UnauthorizedException('Bad payload hash');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function authenticatePayloadHash($calculatedHash, $artifacts)
    {
        if (!hash_equals($calculatedHash, $artifacts['hash'])) {
            throw new UnauthorizedException('Bad payload hash');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function header($credentials, $artifacts, $options = [])
    {
        /*
         * Prepare inputs
         */

        if (!$artifacts ||
            gettype($artifacts) !== 'array' ||
            gettype($options) !== 'array'
        ) {
            throw new ServerException('Invalid inputs');
        }

        if (isset($artifacts['mac'])) {
            unset($artifacts['mac']);
        }

        $artifacts['hash'] = isset($options['hash']) ? $options['hash'] : null;
        $artifacts['ext'] = isset($options['ext']) ? $options['ext'] : null;

        /*
         * Validate credentials
         */

        if (!$credentials ||
            empty($credentials['key']) ||
            empty($credentials['algorithm'])
        ) {
            throw new ServerException('Invalid credentials');
        }

        if (in_array($credentials['algorithm'], $this->Crypto->algorithms) === false) {
            throw new ServerException('Unknown algorithm');
        }

        /*
         * Calculate payload hash
         */

        // Unlike the original Javascript version of Hawk, we need to
        // specifically check if `payload` is defined in the options because
        // PHP throws an "undefined index" error when there is an attempt to use
        // an undefined variable. The original Javascript version of Hawk relied
        // on the fact that Javascript sets an undefined variable a special
        // falsey 'undefined' value, instead of throwing an error.
        if (!$artifacts['hash'] &&
            (!empty($options['payload']) || (isset($options['payload']) && $options['payload'] === ''))
        ) {
            $artifacts['hash'] = $this->Crypto->calculatePayloadHash(
                // If the payload was not defined set it to an empty string.
                // Again, a check not needed in the original Javascript version.
                isset($options['payload']) ? $options['payload'] : '',
                $credentials['algorithm'],
                $options['contentType']
            );
        }

        $mac = $this->Crypto->calculateMac('response', $credentials, $artifacts);

        /*
         * Construct header
         */

        $header = "Hawk mac=\"$mac\"" . ($artifacts['hash'] ? ", hash=\"{$artifacts['hash']}\"" : '');

        if (!is_null($artifacts['ext']) &&
            $artifacts['ext'] !== '' // Other falsey values allowed
        ) {
            $header .= ", ext=\"{$this->Utils->escapeHeaderAttribute($artifacts['ext'])}\"";
        }

        return $header;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticateBewit($request, callable $credentialsFunc, $options = [])
    {
        /*
         * Get application time before any other processing
         */
        $options['localtimeOffsetMsec'] = isset($options['localtimeOffsetMsec'])
            ? $options['localtimeOffsetMsec']
            : 0;
        $now = $this->Utils->now($options['localtimeOffsetMsec']);

        /*
         * Extract bewit
         */

        if (strlen($request['url']) > $this->Utils->limits['maxMatchLength']) {
            throw new BadRequestException('Resource path exceeds max length');
        }

        $resource = [];

        if (!preg_match_all($this->bewitRegex, $request['url'], $resource)) {
            throw new UnauthorizedException();
        }

        // Check if bewit is empty
        if (empty($resource[3][0])) {
            throw new UnauthorizedException('Empty bewit');
        }

        // Check if method is not GET or HEAD
        if (!isset($request['method']) ||
            ($request['method'] !== 'GET' && $request['method'] !== 'HEAD')
        ) {
            throw new UnauthorizedException('Invalid method');
        }

        // Check if there is some other authentication (authorization)
        if (!empty($request['authorization'])) {
            throw new BadRequestException('Multiple authentications');
        }

        // Parse bewit
        try {
            $bewitString = $this->Utils->base64urlDecode($resource[3][0]);
        } catch (\Exception $e) {
            throw new BadRequestException('Invalid bewit encoding');
        }

        // Bewit format: id\exp\mac\ext ('\' is used because it is a reserved
        // header attribute character)
        $bewitParts = explode('\\', $bewitString);

        if (count($bewitParts) !== 4) {
            throw new BadRequestException('Invalid bewit structure');
        }

        $bewit = [
            'id' => $bewitParts[0],
            'exp' => intval($bewitParts[1], 10),
            'mac' => $bewitParts[2],
            'ext' => $bewitParts[3] ? $bewitParts[3] : ''
        ];

        if (!$bewit['id'] ||
            !$bewit['exp'] ||
            !$bewit['mac']
        ) {
            throw new BadRequestException('Missing bewit attributes');
        }

        /*
         * Construct URL without bewit
         */

        $url = $resource[1][0];

        if ($resource[4][0]) {
            $url = $url . $resource[2][0] . $resource[4][0];
        }

        // Check expiration
        if ($bewit['exp'] * 1000 <= $now) {
            throw new UnauthorizedException('Access expired');
        }

        /*
         * Fetch Hawk credentials
         */

        try {
            $credentials = $credentialsFunc($bewit['id']);
        } catch (\Exception $e) {
            throw new ServerException($e->getMessage(), $e->getCode());
        }

        if (!$credentials) {
            throw new UnauthorizedException('Unknown credentials');
        }

        $result = [
            'credentials' => $credentials,
            'attributes' => $bewit
        ];

        if (empty($credentials['key']) || empty($credentials['algorithm'])) {
            throw new ServerException('Invalid credentials');
        }

        if (!in_array($credentials['algorithm'], $this->Crypto->algorithms)) {
            throw new ServerException('Unknown algorithm');
        }

        /*
         * Calculate MAC
         */

        $mac = $this->Crypto->calculateMac('bewit', $credentials, [
            'ts' => $bewit['exp'],
            'nonce' => '',
            'method' => 'GET',
            'resource' => $url,
            'host' => $request['host'],
            'port' => $request['port'],
            'ext' => $bewit['ext']
        ]);

        if (!hash_equals($mac, $bewit['mac'])) {
            throw new UnauthorizedException('Bad MAC');
        }

        // If at this point, then authentication was successful

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticateMessage(
        $host,
        $port,
        $message,
        $authorization,
        callable $credentialsFunc,
        $options = []
    ) {
        /*
         * Default options
         */

        $options['timestampSkewSec'] = empty($options['timestampSkewSec'])
            ? 60
            : $options['timestampSkewSec'];

        /*
         * Get application time before any other processing
         */

        $options['localtimeOffsetMsec'] = isset($options['localtimeOffsetMsec'])
            ? $options['localtimeOffsetMsec']
            : 0;
        $now = $this->Utils->now($options['localtimeOffsetMsec']);

        /*
         * Validate authorization
         */

        if (empty($authorization['id']) ||
            empty($authorization['ts']) ||
            empty($authorization['nonce']) ||
            empty($authorization['hash']) ||
            empty($authorization['mac'])
        ) {
            throw new BadRequestException('Invalid authorization');
        }

        /*
         * Fetch Hawk credentials
         */


        try {
            $credentials = $credentialsFunc($authorization['id']);
        } catch (\Exception $e) {
            throw new ServerException($e->getMessage(), $e->getCode());
        }


        if (!$credentials) {
            throw new UnauthorizedException('Unknown credentials');
        }

        $result = ['credentials' => $credentials];

        if (empty($credentials['key']) || empty($credentials['algorithm'])) {
            throw new ServerException('Invalid credentials');
        }

        if (in_array($credentials['algorithm'], $this->Crypto->algorithms) === false) {
            throw new ServerException('Unknown algorithm');
        }

        /*
         * Construct artifacts container
         */

        $artifacts = [
            'ts' => $authorization['ts'],
            'nonce' => $authorization['nonce'],
            'host' => $host,
            'port' => $port,
            'hash' => $authorization['hash']
        ];

        /*
         * Calculate MAC
         */

        $mac = $this->Crypto->calculateMac('message', $credentials, $artifacts);

        if (!hash_equals($mac, $authorization['mac'])) {
            throw new UnauthorizedException('Bad MAC');
        }

        /*
         * Check payload hash
         */

        $hash = $this->Crypto->calculatePayloadHash($message, $credentials['algorithm']);

        if (!hash_equals($hash, $authorization['hash'])) {
            throw new UnauthorizedException('Bad message hash');
        }

        /*
         * Check nonce
         */

        if (!empty($options['nonceFunc'])) {
            try {
                $options['nonceFunc']($credentials['key'], $authorization['nonce'], $authorization['ts']);
            } catch (\Exception $e) {
                throw new UnauthorizedException('Invalid nonce');
            }
        }

        /*
         * Check timestamp staleness
         */

        if (abs($authorization['ts'] * 1000 - $now) > ($options['timestampSkewSec'] * 1000)) {
            throw new UnauthorizedException('Stale timestamp');
        }

        // If at this point, then authentication was successful

        return $result;
    }
}
