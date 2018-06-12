<?php

namespace Shawm11\Hawk\Utils;

use Shawm11\Hawk\Server\BadRequestException;
use Shawm11\Hawk\Server\UnauthorizedException;

class Utils
{
    /**
     * Limit the length of uris and headers to avoid a DoS attack on string
     * matching
     *
     * @var array
     */
    public $limits = [
        'maxMatchLength' => 4096
    ];

    /**
     * RegEx for matching the host and port portions of the `Host` HTTP header
     * value. Supports domain names, IPv4, and IPv6.
     *
     * @var string
     */
    protected $hostHeaderRegex = "/^(?:(?:\r\n)?\s)*((?:[^:]+)|(?:\[[^\]]+\]))(?::(\d+))?(?:(?:\r\n)?\s)*$/";

    /**
     * RegeEx for matching the `Authorization` HTTP header value.
     *
     * @var string
     */
    protected $authHeaderRegex = "/^(\w+)(?:\s+(.*))?$/";

    /**
     * RegEx for matching attributes within the `Authorization` HTTP header
     * value
     *
     * @var string
     */
    protected $attributeRegex = "/^[ \w\!#\$%&'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~]+$/";

    public function parseContentType($header)
    {
        if (!$header) {
            return '';
        }

        return strtolower(trim(explode(';', $header)[0]));
    }

    public function now($localtimeOffsetMsec)
    {
        $localtimeOffsetMsec = $localtimeOffsetMsec ? $localtimeOffsetMsec : 0;

        return floor(microtime(true) * 1000 + $localtimeOffsetMsec);
    }

    public function nowSecs($localtimeOffsetMsec)
    {
        $localtimeOffsetMsec = $localtimeOffsetMsec ? $localtimeOffsetMsec : 0;

        return floor(microtime(true) + ($localtimeOffsetMsec / 1000));
    }

    public function parseAuthorizationHeader($header, $keys)
    {
        $keys = $keys ? $keys : ['id', 'ts', 'nonce', 'hash', 'ext', 'mac', 'app', 'dlg'];

        if (!$header) {
            throw new UnauthorizedException('Missing Hawk header in request');
        }

        if (strlen($header) > $this->limits['maxMatchLength']) {
            throw new BadRequestException('Header length too long');
        }

        $headerParts = preg_grep($this->authHeaderRegex, $header);

        if (!$headerParts) {
            throw new BadRequestException('Invalid header syntax');
        }

        $scheme = $headerParts[1];

        if (strtolower($scheme) !== 'hawk') {
            throw new UnauthorizedException('Missing Hawk header in request');
        };

        $attributesString = (isset($headerParts[2]) && $headerParts[2]) ? $headerParts[2] : null;

        if (!$attributesString) {
            throw new BadRequestException('Invalid header syntax');
        }

        $attributes = [];
        $errorMessage = '';
        $verify = preg_replace_callback(
            '/(\w+)="([^"\\]*)"\s*(?:,\s*|$)/',
            function ($matches) use ($attributes, $errorMessage) {
                // Check if the attribute name is invalid
                if (in_array($matches[1], $keys) === false) {
                    $errorMessage = 'Unknown attribute: ' . $matches[1];
                    return null;
                }

                // Check if the attribute has characters that are not allowed
                if (!preg_match($this->attributeRegex, $matches[2])) {
                    $errorMessage = 'Bad attribute value: ' . $matches[1];
                    return null;
                }

                // Check if the attribute is a duplicate by checking if the
                // attribute has been processed before
                if ($attributes[$matches[1]]) {
                    $errorMessage = 'Duplicate attribute: ' . $matches[1];
                    return null;
                }

                $attribute[$matches[1]] = $matches[2];

                return '';
            }
        );

        if ($verify !== '') {
            throw new BadRequestException($errorMessage ? $errorMessage : 'Bad header format');
        }

        return $attributes;
    }

    public function escapeHeaderAttribute($attribute)
    {
        // Allowed value characters: !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and space, a-z, A-Z, 0-9, \, "
        if (preg_match("/^[ \w\!#\$%&'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~\"\\]*$/", $attribute)) {
            throw new HawkException("Bad attribute value ($attribute)");
        }

        // Escape quotes and slashes
        return addslashes($attribute);
    }

    public function base64urlEncode($data)
    {
        // Based on the `base64urlEncode()` function in the Hoek NodeJS library
        if (gettype($data) !== 'string') {
            throw new HawkException('Value not a string');
        }

        // Code from http://php.net/manual/en/function.base64-encode.php#103849
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public function base64urlDecode($data)
    {
        // Based on the `base64urlDecode()` function in the Hoek NodeJS library
        if (gettype($data) !== 'string') {
            throw new HawkException('Value not a string');
        }

        // Also based on the `base64urlDecode()` function in the Hoek NodeJS
        // library
        if (!preg_match('/^[\w\-]*$/', $data)) {
            throw new HawkException('Invalid character');
        }

        // Code from http://php.net/manual/en/function.base64-encode.php#103849
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}
