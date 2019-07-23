<?php

namespace Shawm11\Hawk\Utils;

interface UtilsInterface
{
    /**
     * Parse `Content-Type` HTTP header content
     *
     * @param  string  $header  The value of the `Content-Type` HTTP header
     * @return string  The content type
     */
    public function parseContentType($header);

    /**
     * Get the current time with the local time offset in milliseconds
     *
     * @param  float  $localtimeOffsetMsec  Local clock time offset expressed as
     *                                      a number of milliseconds (positive or
     *                                      negative)
     * @return float The current time in milliseconds
     */
    public function now($localtimeOffsetMsec = 0.0);

    /**
     * Get the current time with the local time offset in seconds
     *
     * @param  float  $localtimeOffsetMsec  Local clock time offset express in a
     *                                      number of milliseconds (positive or
     *                                      negative)
     * @return float  The current time in seconds
     */
    public function nowSecs($localtimeOffsetMsec = 0.0);

    /**
     * Parse Hawk HTTP `Authorization` header
     *
     * @param  string  $header  Value of the `Authorization` HTTP header
     * @param  array  $keys  The names of the attributes the Hawk Authorization
     *                       header is supposed to contain. The default is 'id',
     *                       'ts', 'nonce', 'hash', 'ext', 'mac', 'app', and
     *                       'dlg'
     * @throws \Shawm11\Hawk\Server\BadRequestException
     * @throws \Shawm11\Hawk\Server\UnauthorizedException
     * @return array  The attributes of the Hawk Authorization header. Contains
     *                the items listed in `$keys`
     */
    public function parseAuthorizationHeader(
        $header,
        $keys = ['id', 'ts', 'nonce', 'hash', 'ext', 'mac', 'app', 'dlg']
    );

    /**
     * Escape the given attribute value for use in HTTP header
     *
     * @param  string  $attribute  Header attribute value to escape
     * @return string  Escaped attribute value
     */
    public function escapeHeaderAttribute($attribute);

    /**
     * Encode the data given into a URL-safe Base64 encoded string.
     * Follows RFC 4648.
     *
     * @param  string  $data  The data to encode into a URL-safe Base64 string
     * @return string
     */
    public function base64urlEncode($data);

    /**
     * Decode the given URL-safe Base64 string.
     * Follows RFC 4648.
     *
     * @param  string  $data  The URL-safe Base64 string to decode
     * @return string
     */
    public function base64urlDecode($data);
}
