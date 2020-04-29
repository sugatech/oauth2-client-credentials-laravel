<?php

namespace PassportClientCredentials;

use Illuminate\Support\Facades\Cache;
use Zttp\Zttp;

class OAuthClient
{
    /**
     * @var string
     */
    private $oauthUrl;

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
     * @param string $oauthUrl
     * @param int $clientId
     * @param string $clientSecret
     */
    public function __construct($oauthUrl, $clientId, $clientSecret)
    {
        $this->oauthUrl = $oauthUrl;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;

        $this->cacheKey = 'oauth_access_token.' . md5($this->oauthUrl . $this->clientId . $this->clientSecret);
    }

    /**
     * @return array
     */
    private function auth()
    {
        $data = Zttp::withoutVerifying()
            ->post(
                $this->oauthUrl,
                [
                    'grant_type' => 'client_credentials',
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                ]
            )
            ->json();

        Cache::put($this->cacheKey, $data, $data['expires_in']);

        return $data;
    }

    /**
     * @param bool $refresh
     * @return string
     */
    public function getAccessToken($refresh = false)
    {
        if (!$refresh && Cache::has($this->cacheKey)) {
            $data = Cache::get($this->cacheKey);
        } else {
            $data = $this->auth();
        }

        return $data['access_token'];
    }
}