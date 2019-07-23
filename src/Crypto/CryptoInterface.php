<?php

namespace Shawm11\Hawk\Crypto;

interface CryptoInterface
{
    /**
     * Calculate the HMAC digest using the given credentials
     *
     * @param  string  $type  A string that indicates the purpose of the MAC.
     *                        Examples: 'header', 'response', 'bewit', 'message'
     * @param  array  $credentials  Hawk credentials array, which contains
     *                              `key`, and `algorithm`
     * @param  array  $options  Contains `method`, `resource`, `host`, `port`,
     *                          `ts`, `nonce`, `hash`, `ext`, `app`, and `dlg`
     * @return string  The HMAC digest
     */
    public function calculateMac($type, $credentials, $options);

    /**
     * Create a normalized Hawk string that contains the given type and options
     *
     * @param  string  $type  A string that indicates the purpose of the MAC.
     *                        Examples: 'header', 'reponse', 'bewit', 'message'
     * @param  array  $options  Contains `method`, `resource`, `host`, `port`,
     *                          `ts`, `nonce`, `hash`, `ext`, `app`, and `dlg`
     * @return string
     */
    public function generateNormalizedString($type, $options);

    /**
     * Calculate the hash of the given payload and content type
     *
     * @param  string  $payload  Payload for which to calculate the payload
     * @param  string  $algorithm  Hashing algorithm to be used. Either `sha1`
     *                             or `sha256`
     * @param  string  $contentType  Value of the `Content-Type` HTTP header
     * @return string  The hash
     */
    public function calculatePayloadHash($payload, $algorithm, $contentType = null);

    /**
     * Calculate the HMAC digest of the given timestamp using the given
     * credentials
     *
     * @param  string|float  $ts  The timestamp for which to calculate the MAC
     * @param  array  $credentials  Hawk credentials array, which contains
     *                              `key`, `algorithm`, and `user`
     * @return string  The HMAC digest
     */
    public function calculateTsMac($ts, $credentials);

    /**
     * Get the current time and calculate its HMAC using the given credentials
     *
     * @param  array  $credentials  Hawk credentials array, which contains
     *                              `key`, `algorithm`, and `user`
     * @param  float  $localtimeOffsetMsec  Local clock time offset express in a
     *                                      number of milliseconds (positive or
     *                                      negative)
     * @return array  Contains the timestamp for the current time ("now") and
     *                an HMAC digest of the timestamp
     */
    public function timestampMessage($credentials, $localtimeOffsetMsec = 0.0);
}
