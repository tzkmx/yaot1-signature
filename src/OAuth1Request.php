<?php

namespace Apantle\Yaot1;

class OAuth1Request
{
    protected $consumer_secret = '';

    protected $oauth_token_secret = '';

    protected $oauth_params = [];

    protected $query_params = [];

    protected $body_params = [];

    protected $request_uri = '';

    protected $request_method = 'GET';

    /**
     * @param array $oauth_params
     * @return OAuth1Request
     */
    public function setOauthParams(array $oauth_params)
    {
        $this->oauth_params = $oauth_params;
        return $this;
    }

    /**
     * @param array $query_params
     * @return OAuth1Request
     */
    public function setQueryParams(array $query_params)
    {
        $this->query_params = $query_params;
        return $this;
    }

    /**
     * @param array $body_params
     * @return OAuth1Request
     */
    public function setBodyParams(array $body_params)
    {
        $this->body_params = $body_params;
        return $this;
    }

    /**
     * @param string $request_uri
     * @return OAuth1Request
     */
    public function setRequestUri(string $request_uri)
    {
        $this->request_uri = $request_uri;
        return $this;
    }

    /**
     * @param string $request_method
     * @return OAuth1Request
     */
    public function setRequestMethod(string $request_method)
    {
        $this->request_method = $request_method;
        return $this;
    }


    public function getOauthSignature(): string
    {
        $method = strtoupper($this->request_method);
        $baseUri = $this->getUriParsedForSignature();
        $protocolParams = $this->getProtocolParamsString();

        $baseSignatureString =  $method . '&' . $baseUri . '&' . rawurlencode($protocolParams);

        $signatureKey = $this->getOAuthKey();

        $HMAC = hash_hmac('sha1', $baseSignatureString, $signatureKey, $raw = true);

        return rawurlencode(base64_encode($HMAC));
    }

    public function getUriParsedForSignature(): string
    {
        $uriParsed = parse_url($this->request_uri);
        $scheme = strtolower($uriParsed['scheme']);
        $host = strtolower($uriParsed['host']);
        $path = $uriParsed['path'];

        return rawurlencode($scheme. '://' . $host . $path);
    }

    public function getProtocolParamsString(): string
    {
        $params = $this->getOAuthParamsEncoded();

        $paramsString = '';

        foreach ($params as $key => $value) {
            $paramsString .= $key . '=' . $value . '&';
        }

        $length = strlen($paramsString);

        return substr($paramsString, 0, $length - 1);
    }

    public function getOAuthParamsEncoded(): array
    {
        ksort($this->oauth_params);

        $encodedParams = [];
        foreach ($this->oauth_params as $key => $param) {
            if ($this->maybeSkipAndSetSecretKeys($key, $param)) continue;

            $encodedValue = rawurlencode($param);

            $setKey = (strpos($key, 'oauth_') === 0)
                ? $key
                : 'oauth_' . $key
            ;

            $encodedParams[$setKey] = $encodedValue;
        }

        return $encodedParams;
    }

    public function getOAuthKey(): string
    {
        return $this->consumer_secret . '&' .
            $this->oauth_token_secret;
    }

    protected function maybeSkipAndSetSecretKeys(string $key, string $value): bool
    {
        if ($key === 'consumer_secret' || $key === 'oauth_consumer_secret') {
            $this->consumer_secret = $value;
            return true;
        }
        if ($key === 'token_secret' || $key === 'oauth_token_secret') {
            $this->consumer_secret = $value;
            return true;
        }
        return false;
    }
}