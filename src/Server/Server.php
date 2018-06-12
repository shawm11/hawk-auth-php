<?php

namespace Shawm11\Hawk\Server;

class Server
{
    protected $Crypto;
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
        $Crypto = new Crypto;
        $Utils = new Utils;
    }

    public function authenticate($request, callable $credentialsFunc, $options = [])
    {
        /*
         * Default options
         */

        $options['timestampSkewSec'] = (isset($options['timestampSkewSec']) && $options['timestampSkewSec'])
            ? $options['timestampSkewSec']
            : 60;

        /*
         * Get application time before any other processing
         */

        $now = $Utils->now($options['localtimeOffsetMsec']);

        /*
         * Parse HTTP Authorization header
         */

        $attributes = $Utils->parseAuthorizationHeader($request['authorization']);

        /*
         * Construct artifacts container
         */

        $artifacts = [
            'method' => (isset($request['method']) && $request['method']) ? $request['method'] : null,
            'host' => (isset($request['host']) && $request['host']) ? $request['host'] : null,
            'port' => (isset($request['port']) && $request['port']) ? $request['port'] : null,
            'resource' => (isset($request['url']) && $request['url']) ? $request['url'] : null,
            'ts' => (isset($attributes['ts']) && $attributes['ts']) ? $attributes['ts'] : null,
            'nonce' => (isset($attributes['nonce']) && $attributes['nonce']) ? $attributes['nonce'] : null,
            'hash' => (isset($attributes['hash']) && $attributes['hash']) ? $attributes['hash'] : null,
            'ext' => (isset($attributes['ext']) && $attributes['ext']) ? $attributes['ext'] : null,
            'app' => (isset($attributes['app']) && $attributes['app']) ? $attributes['app'] : null,
            'dlg' => (isset($attributes['dlg']) && $attributes['dlg']) ? $attributes['dlg'] : null,
            'mac' => (isset($attributes['mac']) && $attributes['mac']) ? $attributes['mac'] : null,
            'id' => (isset($attributes['id']) && $attributes['id']) ? $attributes['id'] : null
        ];

        /*
         * Verify required header attributes
         */

        if (!$attributes['id'] ||
            !$attributes['ts'] ||
            !$attributes['nonce'] ||
            !$attributes['mac']
        ) {
            throw new ServerException('Missing attributes');
        }

        /*
         * Fetch Hawk credentials
         */

        try {
            $credentials = $credentialsFunc($attributes['id']);
        } catch (\Exception $e) {
            throw new ServerException($e->getMessage());
        }

        if (!$credentials) {
            throw new UnauthorizedException('Unknown credentials');
        }

        $result = [
            'credentials' => $credentials,
            'artifacts' => $artifacts
        ];

        if (!(isset($credentials['key']) && $credentials['key']) ||
            !(isset($credentials['algorithm']) && $credentials['algorithm'])
        ) {
            throw new ServerException('Invalid credentials');
        }

        if (in_array($credentials['algorithm'], $Crypto->algorithms) === false) {
            throw new ServerException('Unknown algorithm');
        }

        /*
         * Calculate MAC
         */

        $mac = $Crypto->calculateMac('header', $credentials, $artifacts);

        if (!hash_equals($mac, $attributes['mac'])) {
            throw new UnauthorizedException('Bad MAC');
        }

        /*
         * Check payload hash
         */

        if ((isset($options['payload']) && $options['payload']) ||
            $options['payload'] === ''
        ) {
            if ((isset($attributes['hash']) && $attributes['hash'])) {
                throw new UnauthorizedException('Missing required payload hash');
            }

            $hash = $Crypto->calculatePayloadHash(
                $options['payload'],
                $credentials['algorithm'],
                $request['contentType']
            );

            if (!hash_equals($hash, $attributes['hash'])) {
                throw new UnauthorizedException('Bad payload hash');
            }
        }

        /*
         * Check nonce
         */

        if (isset($options['nonceFunc']) && $options['nonceFunc']) {
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
            throw new UnauthorizedException('Stale timestamp');
        }

        // If at this point, then authentication was successful

        return $result;
    }

    public function authenticatePayload($payload, $credentials, $artifacts, $contentType)
    {
        $calculatedHash = $Crypto->calculatePayloadHash($payload, $credentials['algorithm'], $contentType);

        if (!hash_equals($calculatedHash, $artifacts['hash'])) {
            throw new UnauthorizedException('Bad payload hash');
        }
    }

    public function authenticatePayloadHash($calculatedHash, $artifacts)
    {
        if (!hash_equals($calculatedHash, $artifacts)) {
            throw new UnauthorizedException('Bad payload hash');
        }
    }

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

        $artifacts['hash'] = $options['hash'];
        $artifacts['ext'] = $options['ext'];

        /*
         * Validate credentials
         */

        if (!$credentials ||
            !(isset($credentials['key']) && $credentials['key']) ||
            !(isset($credentials['algorithm']) && $credentials['algorithm'])
        ) {
            throw new ServerException('Invalid credentials');
        }

        if (in_array($credentials['algorithm'], $Crypto->algorithms) === false) {
            throw new ServerException('Unknown algorithm');
        }

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

        $mac = $Crypto->calculateMac('response', $credentials, $artifacts);

        /*
         * Construct header
         */

        $header = "Hawk mac=\"$mac\"" . ($artifacts['hash'] ? ", hash=\"{$artifacts['hash']}\"" : '');

        if (!isset($artifacts['ext']) &&
            $artifacts['ext'] !== null &&
            $artifacts['ext'] !== '' // Other falsey values allowed
        ) {
            $header .= ", ext=\"{$Utils->escapeHeaderAttribute($artifacts['ext'])}\"";
        }

        return $header;
    }

    public function authenticateBewit($request, callable $credentialsFunc, $options = [])
    {
        /*
         * Get application time before any other processing
         */

        $now = $Utils->now($options['localtimeOffsetMsec']);

        /*
         * Extract bewit
         */

        if (strlen($request['url']) > $Utils->limits['maxMatchLength']) {
            throw BadRequestException('Resource path exceeds max length');
        }

        $resource = preg_grep($this->bewitRegex, $request['url']);

        if (!$resource) {
            throw new UnauthorizedException();
        }

        // Check if bewit is empty
        if (!(isset($resource[3]) && $resource[3])) {
            throw new UnauthorizedException('Empty bewit');
        }

        // Check if method is not GET or HEAD
        if (!isset($request['method']) ||
            ($request['method'] !== 'GET' && $request['method'] !== 'HEAD')
        ) {
            throw new UnauthorizedException('Invalid method');
        }

        // Check if there is some other authentication (authorization)
        if (isset($request['authorization']) && $request['authorization']) {
            throw BadRequestException('Multiple authentications');
        }

        // Parse bewit
        try {
            $bewitString = $Utils->base64urlEncode($resource[3]);
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
            throw BadRequestException('Missing bewit attributes');
        }

        /*
         * Construct URL without bewit
         */

        $url = $resource[1];

        if ($resource[4]) {
            $url = $url . $resource[2] . $resource[4];
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
            throw new ServerException($e->getMessage());
        }

        if (!$credentials) {
            throw new UnauthorizedException('Unknown credentials');
        }

        $result = [
            'credentials' => $credentials,
            'attributes' => $bewit
        ];

        if (!(isset($credentials['key']) && $credentials['key']) ||
            !(isset($credentials['algorithm']) && $credentials['algorithm'])
        ) {
            throw new ServerException('Invalid credentials');
        }

        if (in_array($credentials['algorithm'], $Crypto->algorithms) === false) {
            throw new ServerException('Unknown algorithm');
        }

        /*
         * Calculate MAC
         */

        $mac = $Crypto->calculateMac('bewit', $credentials, [
            'ts' => $bewit['exp'],
            'nonce' => '',
            'method' => 'GET',
            'resource' => $url,
            'host' => $request['host'],
            'port' => $request['port'],
            'ext' => $bewit['ext']
        ]);

        if (!hash_equals($mac, $bewit['mac'])) {
            throw new Unauthorized('Bad MAC');
        }

        // If at this point, then authentication was successful

        return $result;
    }

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

        $options['timestampSkewSec'] = (isset($options['timestampSkewSec']) && $options['timestampSkewSec'])
            ? $options['timestampSkewSec']
            : 60;

        /*
         * Get application time before any other processing
         */

        $now = $Utils->now($options['localtimeOffsetMsec']);

        /*
         * Validate authorization
         */

        if (!$authorization['id'] ||
            !$authorization['ts'] ||
            !$authorization['nonce'] ||
            !$authorization['hash'] ||
            !$authorization['mac']
        ) {
            throw new BadRequestException('Invalid authorization');
        }

        /*
         * Fetch Hawk credentials
         */

        $credentials = $credentialsFunc($authorization['id']);

        if (!$credentials) {
            throw new UnauthorizedException('Unknown credentials');
        }

        $result = ['credentials' => $credentials];

        if (!(isset($credentials['key']) && $credentials['key']) ||
            !(isset($credentials['algorithm']) && $credentials['algorithm'])
        ) {
            throw new ServerException('Invalid credentials');
        }

        if (in_array($credentials['algorithm'], $Crypto->algorithms) === false) {
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

        $mac = $Crypto->calculateTsMac('message', $credentials, $artifacts);

        if (!hash_equals($mac, $authorization['mac'])) {
            throw new UnauthorizedException('Bad mac');
        }

        /*
         * Check payload hash
         */

        $hash = $Crypto->calculatePayloadHash('message', $credentials['algorithm']);

        if (!hash_equals($hash, $authorization['hash'])) {
            throw new UnauthorizedException('Bad message hash');
        }

        /*
         * Check nonce
         */

        if (isset($options['nonceFunc']) && $options['nonceFunc']) {
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
