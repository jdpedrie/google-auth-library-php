<?php
/**
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Google\Auth;

use Google\Auth\Credentials\AppIdentityCredentials;
use Google\Auth\Credentials\GCECredentials;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\Credentials\ServiceAccountJwtAccessCredentials;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use Google\Auth\Middleware\AuthTokenMiddleware;
use GuzzleHttp\Psr7;
use phpseclib\Crypt\RSA;

/**
 * Tools for signing data using a service account or IAM.
 *
 * @see https://cloud.google.com/iam/docs IAM Documentation
 */
class Signer
{
    const IAM_API_ROOT = 'https://iamcredentials.googleapis.com/v1';
    const SIGN_BLOB_PATH = '%s:signBlob?alt=json';
    const SERVICE_ACCOUNT_NAME = 'projects/-/serviceAccounts/%s';

    /**
     * @var callable
     */
    private $httpHandler;

    /**
     * @param callable $httpHandler [optional] The HTTP Handler to send requests.
     */
    public function __construct(callable $httpHandler = null)
    {
        $this->httpHandler = $httpHandler ?: HttpHandlerFactory::build();
    }

    /**
     * Sign a blob using a service account's system-managed private key.
     *
     * This method is intended to be used as a high-level interface, where
     * providing credentials and the string to sign is all that is required.
     *
     * @param FetchAuthTokenInterface $credentials A credentials instance.
     *     Must be {@see Google\Auth\Credentials\ServiceAccountCredentials},
     *     {@see Google\Auth\Credentials\ServiceAccountJwtCredentials} or
     *     {@see Google\Auth\Credentials\GCECredentials}.
     * @param string $stringToSign The data to sign.
     * @param bool $forceOpenssl If true, OpenSSL will be used for service
     *     account signing, regardless of whether phpseclib is available.
     *     **Defaults to** `false`.
     * @return string A base64-encoded signed string.
     */
    public function signBlob(FetchAuthTokenInterface $credentials, $stringToSign, $forceOpenssl = false)
    {
        switch (true) {
            case $credentials instanceof ServiceAccountCredentials:
            case $credentials instanceof ServiceAccountJwtAccessCredentials:
                $privateKey = $credentials->getPrivateKey();
                return $this->signWithPrivateKey($privateKey, $stringToSign, $forceOpenssl);
                break;

            case $credentials instanceof GCECredentials:
            case $credentials instanceof AppIdentityCredentials:
                $serviceAccount = $credentials->fetchServiceAccount($this->httpHandler);
                $authToken = $credentials->fetchAuthToken($this->httpHandler);
                if (!isset($serviceAccount['email']) || !isset($authToken['access_token'])) {
                    throw new \RuntimeException('Could not fetch required signing data.');
                }

                return $this->signWithIam($serviceAccount['email'], $authToken['access_token'], $stringToSign);
                break;

            default:
                throw new \RuntimeException(sprintf(
                    'Signing is not supported with `%s`.',
                    get_class($credentials)
                ));
        }
    }

    /**
     * Sign a string locally using a service account.
     *
     * @param string $privateKey The private key to use in signing.
     * @param string $stringToSign The string to be signed.
     * @param bool $forceOpenssl If true, OpenSSL will be used regardless of
     *     whether phpseclib is available. **Defaults to** `false`.
     * @return string The signed string, base64-encoded.
     */
    public function signWithPrivateKey($privateKey, $stringToSign, $forceOpenssl = false)
    {
        $signedString = '';

        if (class_exists(RSA::class) && !$forceOpenssl) {
            $rsa = new RSA;
            $rsa->loadKey($privateKey);
            $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);
            $rsa->setHash('sha256');

            $signedString = $rsa->sign($stringToSign);
        } elseif (extension_loaded('openssl')) {
            openssl_sign($stringToSign, $signedString, $privateKey, 'sha256WithRSAEncryption');
        } else {
            // @codeCoverageIgnoreStart
            throw new \RuntimeException('OpenSSL is not installed.');
        }
        // @codeCoverageIgnoreEnd

        return base64_encode($signedString);
    }

    /**
     * Sign a string using the IAM signBlob API.
     *
     * @param string $email The service account email.
     * @param string $accessToken An access token from the service account.
     * @param string $stringToSign The string to be signed.
     * @return string The signed string, base64-encoded.
     */
    public function signWithIam($email, $accessToken, $stringToSign)
    {
        $httpHandler = $this->httpHandler;
        $name = sprintf(self::SERVICE_ACCOUNT_NAME, $email);
        $uri = self::IAM_API_ROOT . '/' . sprintf(self::SIGN_BLOB_PATH, $name);

        $body = [
            'delegates' => [
                $name
            ],
            'payload' => base64_encode($stringToSign),
        ];

        $headers = [
            'Authorization' => 'Bearer ' . $accessToken
        ];

        $request = new Psr7\Request(
            'POST',
            $uri,
            $headers,
            Psr7\stream_for(json_encode($body))
        );

        $res = $httpHandler($request);
        $body = json_decode((string) $res->getBody(), true);

        return $body['signedBlob'];
    }
}
