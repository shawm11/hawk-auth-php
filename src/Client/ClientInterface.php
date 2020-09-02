<?php

namespace Shawm11\Hawk\Client;

interface ClientInterface
{
    /**
     * Generate the value for an HTTP `Authorization` header for a request to
     * the server
     *
     * @param  string|array  $uri  URI of the request or an array from
     *                             `parse_url()`
     * @param  string  $method  HTTP verb of the request (e.g. 'GET', 'POST')
     * @param  array  $options  Hawk options that will be integrated in to the
     *                          `Authorization` header value. Includes
     *                          `credentials`, `ext`, `timestamp`, `nonce`,
     *                          `localtimeOffsetMsec`, `payload`, `contentType`,
     *                          `hash`, `app`, and `dlg`
     * @throws ClientException
     * @return array  Contains the `header` (the string the HTTP `Authorization`
     *                header should be set to) and the `artifacts` (the
     *                components used to construct the `header`)
     */
    public function header($uri, $method, $options);

    /**
     * Validate the server's response
     *
     * @param  array  $responseHeaders  An associative array of the HTTP headers
     *                                  in the server's response
     * @param  array  $credentials  Hawk credentials array, which contains
     *                              `key`, `algorithm`, and `user`
     * @param  array  $artifacts  Components used to construct the
     *                            `Authorization` HTTP header in the client's
     *                            request
     * @param  array  $options  Contains `payload` and `required`
     * @throws ClientException  Thrown if the server's response is invalid
     * @return array  The parsed response headers if the server's response is
     *                valid
     */
    public function authenticate($responseHeaders, $credentials, $artifacts, $options = []);

    /**
     * Generate a bewit value for the given URI
     *
     * @param  string|array  $uri  URI for which to generate the bewit or an
     *                             array from `parse_url()`
     * @param  array  $options  Contains `credentials`, `ttlSec`, `ext`, and
     *                          `localtimeOffsetMsec`
     * @throws ClientException
     * @return string  The bewit
     */
    public function getBewit($uri, $options);

    /**
     * Generate an authorization string for the given message
     *
     * @param  string  $host  Host portion of the URI the message will be sent
     *                        to
     * @param  integer  $port  Port of the URI the message will be sent to
     * @param  string|null  $message
     * @param  array  $options  Contains `credentials`, `timestamp`, `nonce`,
     *                          and `localtimeOffsetMsec`
     * @throws ClientException
     * @return array  Contains the authorization string (`mac`) along with the
     *                components used to create the authorization string
     */
    public function message($host, $port, $message, $options);
}
