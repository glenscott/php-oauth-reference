<?php

use GlenScott\OAuth\Consumer;
use GlenScott\OAuth\Token;
use GlenScott\OAuth\SignatureMethod_HMAC_SHA1;
use GlenScott\OAuth\SignatureMethod_PLAINTEXT;
use GlenScott\OAuth\Server;
use GlenScott\OAuth\Request;

require_once dirname(__FILE__) . '/common.php';
require_once dirname(__FILE__) . '/Mock_OAuthDataStore.php';

/**
 * Tests of OAuthUtil
 */
class OAuthServerTest extends PHPUnit_Framework_TestCase {
	private $consumer;
	private $request_token;
	private $access_token;
	private $hmac_sha1;
	private $plaintext;
	private $server;
	
	public function setUp() {
		$this->consumer       = new Consumer('key', 'secret');
		$this->request_token  = new Token('requestkey', 'requestsecret');
		$this->access_token   = new Token('accesskey', 'accesssecret');
		
		$this->hmac_sha1      = new SignatureMethod_HMAC_SHA1();
		$this->plaintext      = new SignatureMethod_PLAINTEXT();
		
		$this->server         = new Server( new Mock_OAuthDataStore() );
		$this->server->add_signature_method( $this->hmac_sha1 );
		$this->server->add_signature_method( $this->plaintext );
	}

	public function testAcceptValidRequest() {
		$request = Request::from_consumer_and_token( $this->consumer, $this->access_token, 'POST', 'http://example.com');
		$request->sign_request( $this->plaintext, $this->consumer, $this->access_token );		
		list($consumer, $token) = $this->server->verify_request( $request );
		$this->assertEquals( $this->consumer, $consumer );
		$this->assertEquals( $this->access_token, $token );
		
		$request->sign_request( $this->hmac_sha1, $this->consumer, $this->access_token );
		list($consumer, $token) = $this->server->verify_request( $request );
		$this->assertEquals( $this->consumer, $consumer );
		$this->assertEquals( $this->access_token, $token );
	}
	
	public function testAcceptRequestWithoutVersion() {
		$request = Request::from_consumer_and_token( $this->consumer, $this->access_token, 'POST', 'http://example.com');
		$request->unset_parameter('oauth_version');
		$request->sign_request( $this->hmac_sha1, $this->consumer, $this->access_token );
	
		$this->server->verify_request( $request );
	}
	
	public function testRejectRequestSignedWithRequestToken() {
		$request = Request::from_consumer_and_token( $this->consumer, $this->request_token, 'POST', 'http://example.com');
		$request->sign_request( $this->plaintext, $this->consumer, $this->request_token );		
		
		$this->setExpectedException('GlenScott\OAuth\Exception');
		$this->server->verify_request( $request );
	}
	
	public function testRejectRequestWithMissingParameters() {
		// The list of required parameters is taken from
		// Chapter 7 ("Accessing Protected Resources")
		
		$required_parameters = array(
			'oauth_consumer_key',
			'oauth_token',
			'oauth_signature_method',
			'oauth_signature',
			'oauth_timestamp',
			'oauth_nonce'
		);
		
		foreach( $required_parameters AS $required ) {
			$request = Request::from_consumer_and_token( $this->consumer, $this->access_token, 'POST', 'http://example.com');
			$request->sign_request( $this->plaintext, $this->consumer, $this->access_token );
			try {
				$request->unset_parameter( $required );
				$this->server->verify_request($request);
				$this->fail('Allowed a request without `' . $required . '`');
			} catch( GlenScott\OAuth\Exception $e ) { /* expected */ }
		}
	}
		
	public function testRejectPastTimestamp() {
		// We change the timestamp to be 10 hours ago, it should throw an exception
		
		$request = Request::from_consumer_and_token( $this->consumer, $this->access_token, 'POST', 'http://example.com');
		$request->set_parameter( 'oauth_timestamp', $request->get_parameter('oauth_timestamp') - 10*60*60, false);
		$request->sign_request( $this->plaintext, $this->consumer, $this->access_token );
		
		$this->setExpectedException('GlenScott\OAuth\Exception');
		$this->server->verify_request($request);
	}
	
	public function testRejectFutureTimestamp() {
		// We change the timestamp to be 10 hours in the future, it should throw an exception
		
		$request = Request::from_consumer_and_token( $this->consumer, $this->access_token, 'POST', 'http://example.com');
		$request->set_parameter( 'oauth_timestamp', $request->get_parameter('oauth_timestamp') + 10*60*60, false);
		$request->sign_request( $this->plaintext, $this->consumer, $this->access_token );
		
		$this->setExpectedException('GlenScott\OAuth\Exception');
		$this->server->verify_request($request);
	}
	
	public function testRejectUsedNonce() {
		// We give a known nonce and should see an exception
	
		$request = Request::from_consumer_and_token( $this->consumer, $this->access_token, 'POST', 'http://example.com');
		// The Mock datastore is set to say that the `nonce` nonce is known
		$request->set_parameter( 'oauth_nonce', 'nonce', false);
		$request->sign_request( $this->plaintext, $this->consumer, $this->access_token );

		$this->setExpectedException('GlenScott\OAuth\Exception');
		$this->server->verify_request($request);
	}
	
	public function testRejectInvalidSignature() {
		// We change the signature post-signing to be something invalid
	
		$request = Request::from_consumer_and_token( $this->consumer, $this->access_token, 'POST', 'http://example.com');
		$request->sign_request( $this->plaintext, $this->consumer, $this->access_token );
		$request->set_parameter( 'oauth_signature', '__whatever__', false);

		$this->setExpectedException('GlenScott\OAuth\Exception');
		$this->server->verify_request($request);
	}
	
	public function testRejectInvalidConsumer() {
		// We use the consumer-key "unknown", which isn't known by the datastore. 
		
		$unknown_consumer = new Consumer('unknown', '__unused__');
			
		$request = Request::from_consumer_and_token( $unknown_consumer, $this->access_token, 'POST', 'http://example.com');
		$request->sign_request( $this->plaintext, $unknown_consumer, $this->access_token );
		
		$this->setExpectedException('GlenScott\OAuth\Exception');
		$this->server->verify_request( $request );	
	}
	
	public function testRejectInvalidToken() {
		// We use the access-token "unknown" which isn't known by the datastore
		
		$unknown_token = new Token('unknown', '__unused__');
			
		$request = Request::from_consumer_and_token( $this->consumer, $unknown_token, 'POST', 'http://example.com');
		$request->sign_request( $this->plaintext, $this->consumer, $unknown_token );
		
		$this->setExpectedException('GlenScott\OAuth\Exception');
		$this->server->verify_request( $request );	
	}
	
	public function testRejectUnknownSignatureMethod() {
		// We use a server that only supports HMAC-SHA1, but requests with PLAINTEXT signature
		
		$request = Request::from_consumer_and_token( $this->consumer, $this->access_token, 'POST', 'http://example.com');
		$request->sign_request( $this->plaintext, $this->consumer, $this->access_token );
		
		$server = new Server( new Mock_OAuthDataStore() );
		$server->add_signature_method( $this->hmac_sha1 );
		
		$this->setExpectedException('GlenScott\OAuth\Exception');
		$server->verify_request( $request );	
	}
	
	public function testRejectUnknownVersion() {
		// We use the version "1.0a" which isn't "1.0", so reject the request
		
		$request = Request::from_consumer_and_token( $this->consumer, $this->access_token, 'POST', 'http://example.com');
		$request->sign_request( $this->plaintext, $this->consumer, $this->access_token );
		$request->set_parameter('oauth_version', '1.0a', false);
		
		$this->setExpectedException('GlenScott\OAuth\Exception');
		$this->server->verify_request( $request );	
	}
	
	public function testCreateRequestToken() {
		// We request a new Request Token
		
		$request = Request::from_consumer_and_token( $this->consumer, NULL, 'POST', 'http://example.com');
		$request->sign_request( $this->plaintext, $this->consumer, NULL );
		
		$token = $this->server->fetch_request_token($request);
		$this->assertEquals($this->request_token, $token);
	}
	
	public function testRejectSignedRequestTokenRequest() {
		// We request a new Request Token, but the request is signed with a token which should fail
		
		$request = Request::from_consumer_and_token( $this->consumer, $this->request_token, 'POST', 'http://example.com');
		$request->sign_request( $this->plaintext, $this->consumer, $this->request_token );
		
		$this->setExpectedException('GlenScott\OAuth\Exception');
		$token = $this->server->fetch_request_token($request);
	}
	
	public function testCreateAccessToken() {
		// We request a new Access Token
		
		$request = Request::from_consumer_and_token( $this->consumer, $this->request_token, 'POST', 'http://example.com');
		$request->sign_request( $this->plaintext, $this->consumer, $this->request_token );
		
		$token = $this->server->fetch_access_token($request);
		$this->assertEquals($this->access_token, $token);
	}
	
	public function testRejectUnsignedAccessTokenRequest() {
		// We request a new Access Token, but we didn't sign the request with a Access Token
		
		$request = Request::from_consumer_and_token( $this->consumer, NULL, 'POST', 'http://example.com');
		$request->sign_request( $this->plaintext, $this->consumer, NULL );
		
		$this->setExpectedException('GlenScott\OAuth\Exception');
		$token = $this->server->fetch_access_token($request);
	}
	
	public function testRejectAccessTokenSignedAccessTokenRequest() {
		// We request a new Access Token, but the request is signed with an access token, so fail!
		
		$request = Request::from_consumer_and_token( $this->consumer, $this->access_token, 'POST', 'http://example.com');
		$request->sign_request( $this->plaintext, $this->consumer, $this->access_token );
		
		$this->setExpectedException('GlenScott\OAuth\Exception');
		$token = $this->server->fetch_access_token($request);
	}
}
