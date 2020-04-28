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
    }

    /**
     * @return string
     */
    public function getAccessToken()
    {
        if (Cache::has($this->baseUrl)) {
            return Cache::get($this->baseUrl);
        }

        $response = Zttp::withoutVerifying()
            ->post(
                $this->baseUrl,
                [
                    'grant_type' => 'client_credentials',
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                ]
            )
            ->json();

        Cache::add($this->baseUrl, $response['access_token'], $response['expires_in']);

        return $response['access_token'];
    }

    /**
     * @return string
     */
    public function resetToken()
    {
        Cache::forget($this->baseUrl);

        $response = Zttp::withoutVerifying()
            ->post(
                $this->baseUrl,
                [
                    'grant_type' => 'client_credentials',
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                ]
            )
            ->json();

        Cache::add($this->baseUrl, $response['access_token'], $response['expires_in']);

        return $response['access_token'];
    }
}