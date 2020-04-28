<?php

namespace PassportClientCredentials;

use Illuminate\Support\Facades\Cache;
use Zttp\Zttp;

class AuthRequest
{
    /**
     * @var string
     */
    private $baseUrl;

    /**
     * @var int
     */
    private $clientId;

    /**
     * @var string
     */
    private $clientSecret;

    /**
     * @var string
     */
    private $cacheKey;

    /**
     * AuthRequest constructor.
     * @param string $baseUrl
     * @param int $clientId
     * @param string $clientSecret
     */
    public function __construct($baseUrl, $clientId, $clientSecret)
    {
        $this->baseUrl = $baseUrl;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;

        $this->cacheKey = md5($this->baseUrl . $this->clientId . $this->clientSecret);
    }

    /**
     * @return array
     */
    private function request()
    {
        return Zttp::withoutVerifying()
            ->post(
                $this->baseUrl,
                [
                    'grant_type' => 'client_credentials',
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                ]
            )
            ->json();
    }

    /**
     * @return string
     */
    public function getAccessToken()
    {
        if (Cache::has($this->cacheKey)) {
            return Cache::get($this->cacheKey);
        }

        $response = $this->request();

        Cache::add($this->cacheKey, $response['access_token'], $response['expires_in']);

        return $response['access_token'];
    }

    /**
     * @return string
     */
    public function refreshAccessToken()
    {
        Cache::forget($this->cacheKey);

        $response = $this->request();

        Cache::add($this->cacheKey, $response['access_token'], $response['expires_in']);

        return $response['access_token'];
    }
}