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

namespace Google\Auth\Tests;

use Google\Auth\Signer;
use GuzzleHttp\Psr7\Response;
use phpseclib\Crypt\RSA;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Psr\Http\Message\RequestInterface;

class SignerTest extends TestCase
{
    /**
     * @dataProvider serviceAccountCredentials
     */
    public function testSignBlobServiceAccount($credentials)
    {
        $httpHandler = function () {};
        $signer = new SignerStub($httpHandler);

        $credentials->getPrivateKey()->shouldBeCalled()
            ->willReturn('foobar');

        $res = $signer->signBlob($credentials->reveal(), 'hello world');

        $this->assertEquals([
            'signWithPrivateKey',
            [
                'foobar',
                'hello world',
                false
            ]
        ], $res);
    }

    public function serviceAccountCredentials()
    {
        return [
            [$this->prophesize('Google\Auth\Credentials\ServiceAccountCredentials')],
            [$this->prophesize('Google\Auth\Credentials\ServiceAccountJwtAccessCredentials')],
        ];
    }

    /**
     * @dataProvider iamCredentials
     */
    public function testSignBlobIam($credentials)
    {
        $httpHandler = function () {};
        $signer = new SignerStub($httpHandler);

        $credentials->fetchServiceAccount(Argument::type('callable'))->shouldBeCalled()
            ->willReturn([
                'email' => 'foo@bar.com'
            ]);

        $credentials->fetchAuthToken(Argument::type('callable'))->shouldBeCalled()
            ->willReturn([
                'access_token' => 'foobar'
            ]);

        $res = $signer->signBlob($credentials->reveal(), 'hello world');

        $this->assertEquals([
            'signWithIam',
            [
                'foo@bar.com',
                'foobar',
                'hello world'
            ]
        ], $res);
    }

    public function iamCredentials()
    {
        return [
            [$this->prophesize('Google\Auth\Credentials\GCECredentials')],
            [$this->prophesize('Google\Auth\Credentials\AppIdentityCredentials')],
        ];
    }

    /**
     * @dataProvider credentialsMissingData
     * @expectedException \RuntimeException
     */
    public function testSignBlobIamMissingData(array $serviceAccount, array $accessToken)
    {
        $credentials = $this->prophesize('Google\Auth\Credentials\GCECredentials');
        $credentials->fetchServiceAccount(Argument::any())->willReturn($serviceAccount);
        $credentials->fetchAuthToken(Argument::any())->willReturn($accessToken);

        $signer = new Signer(function () {});
        $signer->signBlob($credentials->reveal(), 'hello world');
    }

    public function credentialsMissingData()
    {
        return [
            [
                [], [
                    'access_token' => ''
                ]
            ], [
                [
                    'email' => '',
                ], []
            ]
        ];
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testSignWithInvalidCredentials()
    {
        $httpHandler = function () {};
        $signer = new SignerStub($httpHandler);

        $credentials = $this->prophesize('Google\Auth\Credentials\InsecureCredentials');

        $signer->signBlob($credentials->reveal(), 'foobar');
    }

    /**
     * @dataProvider usessl
     */
    public function testSignWithPrivateKey($forceOpenssl)
    {
        $privatekey = $this->getKeyPair()[0];

        $input = 'hello world';

        $signer = new Signer(function () {});
        $signature = $signer->signWithPrivateKey($privatekey, $input, $forceOpenssl);

        $this->assertSignatureMatches($privatekey, $input, base64_decode($signature));
    }

    public function usessl()
    {
        return [
            [true],
            [false]
        ];
    }

    public function testSignWithIam()
    {
        $input = 'hello world';
        $accessToken = 'foobar';
        $email = 'foo@bar.com';
        $output = 'signedstringvalue';

        $httpHandler = function (RequestInterface $request) use ($input, $accessToken, $email, $output) {
            $name = sprintf(Signer::SERVICE_ACCOUNT_NAME, $email);
            $expectedUri = Signer::IAM_API_ROOT . '/' . sprintf(Signer::SIGN_BLOB_PATH, $name);
            $headers = $request->getHeaders();
            $body = json_decode((string) $request->getBody(), true);

            $this->assertEquals($expectedUri, $request->getUri());
            $this->assertArrayHasKey('Authorization', $headers);
            $this->assertEquals('Bearer ' . $accessToken, $headers['Authorization'][0]);
            $this->assertEquals($name, $body['delegates'][0]);
            $this->assertEquals(base64_encode($input), $body['payload']);

            return new Response(200, [], json_encode([
                'signedBlob' => $output
            ]));
        };

        $signer = new Signer($httpHandler);

        $res = $signer->signWithIam($email, $accessToken, $input);

        $this->assertEquals($output, $res);
    }

    private function getKeyPair()
    {
        $rsa = new RSA;
        $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);
        $rsa->setHash('sha256');
        $key = $rsa->createKey();
        usleep(500);
        return [$key['privatekey'], $key['publickey']];
    }

    private function assertSignatureMatches($privateKey, $input, $signature)
    {
        $rsa = new RSA;
        $rsa->loadKey($privateKey);
        $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);
        $rsa->setHash('sha256');

        $signedString = $rsa->sign($input);

        $this->assertEquals($signature, $signedString);
    }
}

class SignerStub extends Signer
{
    public function signWithPrivateKey($privateKey, $stringToSign, $forceOpenssl = false)
    {
        return ['signWithPrivateKey', func_get_args()];
    }

    public function signWithIam($email, $accessToken, $stringToSign)
    {
        return ['signWithIam', func_get_args()];
    }
}
