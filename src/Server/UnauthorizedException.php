<?php

namespace Shawm11\Hawk\Server;

class UnauthorizedException extends ServerException
{
    /**
     * Keys & values the include in the `WWW-Authenticate`
     *
     * @var array
     */
    protected $wwwAuthenticateHeaderAttributes = [];

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

        $this->wwwAuthenticateHeaderAttributes = $wwwAuthenticateHeaderAttributes;
    }

    /**
     * Get the associative array of keys & values included in the
     * `WWW-Authenticate`
     *
     * @return array
     */
    public function getWwwAuthenticateHeaderAttributes()
    {
        return $this->wwwAuthenticateHeaderAttributes;
    }

    /**
     * Get the value the HTTP `WWW-Authenticate` header should be set to in the
     * server's response.
     *
     * @return string
     */
    public function getWwwAuthenticateHeader()
    {
        $wwwAuthenticateHeader = 'Hawk';

        foreach ($this->wwwAuthenticateHeaderAttributes as $key => $value) {
            $value = is_null($value) ? '': $value;

            $wwwAuthenticateHeader .= " $key=\"$value\",";
        }

        if ($this->message) {
            $wwwAuthenticateHeader .= " error=\"$this->message\"";
        } else {
            // Remove comma at the end
            $wwwAuthenticateHeader = rtrim($wwwAuthenticateHeader, ',');
        }

        return $wwwAuthenticateHeader;
    }
}
