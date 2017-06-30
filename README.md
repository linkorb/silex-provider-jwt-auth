# linkorb/silex-provider-jwt-auth

Provides a firewall which uses, as its authentication provider, an issuer of
Json Web Tokens.


## Install

Install using composer:-

    $ composer require linkorb/silex-provider-jwt-auth

Then configure and register the provider along with the Silex Session and
Security providers:-

    // app/app.php
    use LinkORB\JwtAuth\Provider\JwtAuthenticatorServiceProvider;
    use Silex\Provider\SecurityServiceProvider;
    use Silex\Provider\SessionServiceProvider;
    ...
    $app->register(new SessionServiceProvider);
    $app->register(
        new SecurityServiceProvider,
        [
            'security.firewalls' => [
                'my_firewall' => [
                    'pattern' => '^/secure-area',
                    'stateless' => false,
                    'jwt_issuer' => [
                        'jwt_issuer_url' => 'https://example.com/issue/a/jwt',
                        // see JwtAuthenticatorServiceProvider for more options
                    ],
                    'users' => function () use ($app) {
                        return $app['my_user_provider'];
                    },
                ],
            ],
        ]
    );
    $app->register(
        new JwtAuthenticatorServiceProvider,
        [
            'jwt_auth.decoder.config' => [
                'decoder_key' => function () {
                    return file_get_contents('/path/to/jwt/decoder/key.pub');
                },
                'permitted_algos' => ['RS256', 'RS384', 'RS512'],
            ],
        ]
    );
