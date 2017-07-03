<?php

namespace LinkORB\JwtAuth\Security\EntryPoint;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * Start authentication by redirecting to a configurable URL.
 *
 * The resource currently being requested is sent in the query string in the
 * expectation that it will be returned to the authentication endpoint as part
 * of the Json Web Token.
 *
 */
class JwtAuthenticationEntryPoint implements AuthenticationEntryPointInterface
{
    /**
     * Name of a request url query parameter with which to provide the path on
     * this host from which the request originates.
     *
     * @var string
     */
    const ORIGIN_PARAM = 'origin';

    /**
     * @var string
     */
    private $issuerUrl;
    /**
     * @var array
     */
    private $options;

    /**
     * @param string $issuerUrl Url from where a Json Web Token may be obtained.
     * @param array $options Options.
     */
    public function __construct($issuerUrl, array $options = [])
    {
        $this->issuerUrl = $issuerUrl;
        $this->options = $options;
    }

    /**
     * Redirect to a resource from where the requestor may obtain a Json Web Token.
     *
     * {@inheritDoc}
     */
    public function start(
        Request $request,
        AuthenticationException $authException = null
    ) {
        return new RedirectResponse(
            $this->buildUrl(rawurlencode($request->getRequestUri()))
        );
    }

    private function optOriginParam()
    {
        return isset($this->options['jwt_issuer_url_origin_param'])
            ? $this->options['jwt_issuer_url_origin_param']
            : self::ORIGIN_PARAM
        ;
    }

    /*
     * Deconstruct the issuerUrl, add the origin query param and reconstruct.
     * Won't handle an issuerUrl in which the host is an IPv6 addr.
     */
    private function buildUrl($origin)
    {
        $u = parse_url($this->issuerUrl);

        if (isset($u['query'])) {
            $q = [];
            parse_str($u['query'], $q);
            $q[$this->optOriginParam()] = $origin;
            $u['query'] = http_build_query($q);
        } else {
            $u['query'] = http_build_query(
                [$this->optOriginParam() => $origin]
            );
        }

        $url = '';
        if (isset($u['scheme'])) {
            $url .= "{$u['scheme']}://";
        } else {
            $url = 'https://';
        }
        if (isset($u['user'])) {
            $url .= $u['user'];
            if (isset($u['pass'])) {
                $url .= ":{$u['pass']}";
            }
            $url .= '@';
        }
        $url .= $u['host'];
        if (isset($u['port'])) {
            $url .= ":{$u['port']}";
        }
        if (isset($u['path'])) {
            $url .= $u['path'];
        } else {
            $url .= '/';
        }
        $url .= "?{$u['query']}";
        if (isset($u['fragment'])) {
            $url .= "#{$u['fragment']}";
        }

        return $url;
    }
}
