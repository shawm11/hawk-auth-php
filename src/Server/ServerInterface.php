<?php

namespace Shawm11\Hawk\Server;

interface ServerInterface
{
    /**
     * Validate the given request from a client
     *
     * @param  array  $request  Request data, which contains `method`, `url`,
     *                          `host`, `port`, `authorization`, and
     *                          `contentType`
     * @param  callable  $credentialsFunc  Required function for looking up the
     *                                     set of Hawk credentials based on the
     *                                     provided credentials ID. It Includes
     *                                     the MAC key, MAC algorithm, and other
     *                                     attributes (such as username) needed
     *                                     by the application. It is the same
     *                                     as verifying the username and
     *                                     password in HTTP Basic
     *                                     authentication.
     * @param  array  $options  Includes `nonceFunc`, `timestampSkewSec`,
     *                          `localtimeOffsetMsec`, `payload`, `host`, and
     *                          `port`
     * @throws ServerException  Thrown if the client's request is invalid
     * @return array  Includes the retrieved credentials and the components of
     *                Authorization header (artifacts) if the request was valid
     */
    public function authenticate($request, callable $credentialsFunc, $options = []);

    /**
     * Authenticate payload hash using the payload, credentials, content type to
     * calculate the hash. Only used when payload cannot be provided during
     * `authenticate()`.
     *
     * @param  string  $payload  Raw request payload
     * @param  array  $credentials  Credentials returned by `authenticate()`
     * @param  array  $artifacts  Artifacts returned by `authenticate()`
     * @param  string  $contentType  Value of the `Content-Type` HTTP header in
     *                               the request from the client
     * @return void
     */
    public function authenticatePayload($payload, $credentials, $artifacts, $contentType);

    /**
     * Authenticate payload hash using the given pre-calculated hash. Only used
     * when payload cannot be provided during `authenticate()`.
     *
     * @param  string  $calculatedHash
     * @param  array  $artifacts  Artifacts returned by `authenticate()`
     * @return void
     */
    public function authenticatePayloadHash($calculatedHash, $artifacts);

    /**
     * Generate the value for the `Server-Authorization` header for the given
     * response (response data contained in the artifacts)
     *
     * @param  array  $credentials  Credentials returned by `authenticate()`
     * @param  array  $artifacts  Artifacts returned by `authenticate()`
     * @param  array  $options  Hawk attributes that will be integrated into the
     *                          `Server-Authorization` header value. Includes
     *                          `ext`, `payload`, `contentType`, and `hash`
     * @return string  Value for the `Server-Authorization` header
     */
    public function header($credentials, $artifacts, $options = []);

    /**
     * Validate the bewit contained in the given request URL
     *
     * @param  array  $request  Request data, which contains `method`, `url`,
     *                          `host`, `port`, and `authorization`
     * @param  callable  $credentialsFunc  Required function to lookup the set
     *                                     of Hawk credentials based on the
     *                                     provided credentials ID. It Includes
     *                                     the MAC key, MAC algorithm, and other
     *                                     attributes (such as username) needed
     *                                     by the application. It is the same
     *                                     as verifying the username and
     *                                     password in HTTP Basic
     *                                     authentication.
     * @param  array  $options  Includes `localtimeOffsetMsec`, `host`, and
     *                          `port`
     * @throws ServerException Thrown if the bewit is invalid
     * @return array  Includes the retrieved credentials and the components of
     *                bewit (attributes) if the bewit was valid
     */
    public function authenticateBewit($request, callable $credentialsFunc, $options = []);

    /**
     * Validate the given message against the given authorization string
     *
     * @param  string  $host  Host portion of the URI the request was made to
     * @param  integer  $port  Port of the URI the request was made to
     * @param  string  $message  The message to validate
     * @param  array  $authorization  Components used to create authorization
     *                                string for the message
     * @param  callable  $credentialsFunc  Function to lookup the set of Hawk
     *                                     credentials based on the provided
     *                                     credentials ID
     * @param  array  $options  Includes `nonceFunc`, `timestampSkewSec`, and
     *                          `localtimeOffsetMsec`
     * @throws ServerException Thrown if the message is invalid
     * @return array  The retrieved credentials if the message is valid
     */
    public function authenticateMessage(
        $host,
        $port,
        $message,
        $authorization,
        callable $credentialsFunc,
        $options = []
    );
}
