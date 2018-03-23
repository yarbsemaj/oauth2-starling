<?php

namespace AdamPaterson\OAuth2\Client\Provider;

use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class Starling extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * Get authorization url to begin OAuth flow
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return 'https://oauth.starlingbank.com/';
    }

    /**
     * Get access token url to retrieve token
     *
     * @param array $params
     *
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return 'https://api.starlingbank.com/oauth/access-token';
    }

    /**
     * Get provider url to fetch user details
     *
     * @param AccessToken $token
     *
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return 'developer.starlingbank.com/api/v1/me';
    }


    /**
     * Get the default scopes used by this provider.
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return ['balance:read','transaction:read','payee:read','mandate:read','savings-goal:read','savings-goal-transfer:read'];
    }

    /**
     * Check a provider response for errors.
     *
     * @param ResponseInterface $response
     * @param array|string $data
     *
     * @throws IdentityProviderException
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($response->getStatusCode() >= 400) {
            throw new IdentityProviderException(
                $data['error'] ?: $response->getReasonPhrase(),
                $response->getStatusCode(),
                $response
            );
        }
    }

    /**
     * Generate a user object from a successful user details request.
     *
     * @param array $response
     * @param AccessToken $token
     *
     * @return StarlingResourceOwner
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new StarlingResourceOwner($response);
    }

    protected function createAccessToken(array $response, AbstractGrant $grant)
    {
        $accessToken = parent::createAccessToken($response, $grant);

        // create the parent access token and add properties from response
        foreach ($response as $k => $v) {
            if (!property_exists($accessToken, $k)) {
                $accessToken->$k = $v;
            }
        }

        return $accessToken;
    }

    /**
     * @param string $stripeUserId stripe account ID
     *
     * @return mixed
     */
    public function deauthorize($stripeUserId)
    {
        $request = $this->createRequest(
            self::METHOD_POST,
            $this->getBaseDeauthorizationUrl(),
            null,
            [
                'body' => $this->buildQueryString([
                    'stripe_user_id' => $stripeUserId,
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                ]),
            ]
        );

        return $this->getParsedResponse($request);
    }
}
