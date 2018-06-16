<?php

namespace Shawm11\Hawk\Server;

class UnauthorizedException extends ServerException
{
    /**
     * The value of the `WWW-Authenticate` header for server's response
     *
     * @var string
     */
    protected $wwwAuthenticateHeader;

    /**
     * @param string  $message  The Exception message to throw. It is also
     *                          included in the `WWW-Authenticate` header.
     * @param array  $wwwAuthenticateHeaderAttributes  Associative array of keys
     *                                                 & values the include in
     *                                                 the `WWW-Authenticate`
     *                                                 header in the format:
     *                                                 `<key>:"<value>"`
     * @param integer  $code  HTTP status code that the response should have
     * @param \Throwable  $previous  The previous exception used for the
     *                               exception chaining
     */
    public function __construct($message = '', $wwwAuthenticateHeaderAttributes = [], $code = 401, $previous = null)
    {
        parent::__construct($message, $code, $previous);

        /*
         * Create WWW-Authenticate header value for server's response
         */

        $this->wwwAuthenticateHeader = 'Hawk';

        foreach ($wwwAuthenticateHeaderAttributes as $key => $value) {
            $value = $value === null ? '': $value;

            $this->wwwAuthenticateHeader .= " $key=\"$value\",";
        }

        if ($message) {
            $this->wwwAuthenticateHeader .= " error=\"$message\"";
        } else {
            // Remove comma at the end
            $this->wwwAuthenticateHeader = rtrim($this->wwwAuthenticateHeader, ',');
        }
    }

    /**
     * Get the value the HTTP `WWW-Authenticate` header should be set to in the
     * server's response.
     *
     * @return string
     */
    public function getWwwAuthenticateHeader()
    {
        return $this->wwwAuthenticateHeader;
    }
}
