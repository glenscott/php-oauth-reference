<?php

use GlenScott\OAuth\Util;

require_once dirname(__FILE__) . '/common.php';

/**
 * Tests of OAuthUtil
 */
class OAuthUtilTest extends PHPUnit_Framework_TestCase {
	public function testUrlencode() {
		// Tests taken from
		// http://wiki.oauth.net/TestCases ("Parameter Encoding")
		$this->assertEquals('abcABC123', Util::urlencode_rfc3986('abcABC123'));
		$this->assertEquals('-._~',      Util::urlencode_rfc3986('-._~'));
		$this->assertEquals('%25',       Util::urlencode_rfc3986('%'));
		$this->assertEquals('%2B',       Util::urlencode_rfc3986('+'));
		$this->assertEquals('%0A',       Util::urlencode_rfc3986("\n"));
		$this->assertEquals('%20',       Util::urlencode_rfc3986(' '));
		$this->assertEquals('%7F',       Util::urlencode_rfc3986("\x7F"));
		//$this->assertEquals('%C2%80',    Util::urlencode_rfc3986("\x00\x80"));
		//$this->assertEquals('%E3%80%81', Util::urlencode_rfc3986("\x30\x01"));
		
		// Last two checks disabled because of lack of UTF-8 support, or lack
		// of knowledge from me (morten.fangel) on how to use it properly..
		
		// A few tests to ensure code-coverage
		$this->assertEquals( '', Util::urlencode_rfc3986(NULL));
		$this->assertEquals( '', Util::urlencode_rfc3986(new stdClass()));
	}

	public function testUrldecode() {
		// Tests taken from
		// http://wiki.oauth.net/TestCases ("Parameter Encoding")
		$this->assertEquals('abcABC123', Util::urldecode_rfc3986('abcABC123'));
		$this->assertEquals('-._~',      Util::urldecode_rfc3986('-._~'));
		$this->assertEquals('%',         Util::urldecode_rfc3986('%25'));
		$this->assertEquals('+',         Util::urldecode_rfc3986('%2B'));
		$this->assertEquals("\n",        Util::urldecode_rfc3986('%0A'));
		$this->assertEquals(' ',         Util::urldecode_rfc3986('%20'));
		$this->assertEquals("\x7F",      Util::urldecode_rfc3986('%7F'));
		//$this->assertEquals("\x00\x80",  Util::urldecode_rfc3986('%C2%80'));
		//$this->assertEquals("\x30\x01",  Util::urldecode_rfc3986('%E3%80%81'));
		
		// Last two checks disabled because of lack of UTF-8 support, or lack
		// of knowledge from me (morten.fangel) on how to use it properly..
	}
	
	public function testParseParameter() {
		// Tests taken from
		// http://wiki.oauth.net/TestCases ("Normalize Request Parameters")
	
		$this->assertEquals(
			array('name'=>''), 
			Util::parse_parameters('name')
		);
		$this->assertEquals(
			array('a'=>'b'),
			Util::parse_parameters('a=b')
		);
		$this->assertEquals(
			array('a'=>'b','c'=>'d'),
			Util::parse_parameters('a=b&c=d')
		);
		$this->assertEquals(
			array('a'=>array('x!y','x y')),
			Util::parse_parameters('a=x!y&a=x+y')
		);
		$this->assertEquals(
			array('x!y'=>'a', 'x' =>'a'),
			Util::parse_parameters('x!y=a&x=a')
		);
	}
	
	public function testBuildHttpQuery() {
		// Tests taken from
		// http://wiki.oauth.net/TestCases ("Normalize Request Parameters")
		$this->assertEquals(
		    'name=',
			Util::build_http_query(array('name'=>''))
		);
		$this->assertEquals(
			'a=b',
			Util::build_http_query(array('a'=>'b'))
		);
		$this->assertEquals(
			'a=b&c=d',
			Util::build_http_query(array('a'=>'b','c'=>'d'))
		);
		$this->assertEquals(
			'a=x%20y&a=x%21y',
			Util::build_http_query(array('a'=>array('x!y','x y')))
		);
		$this->assertEquals(
			'x=a&x%21y=a',
			Util::build_http_query(array('x!y'=>'a', 'x' =>'a'))
		);
		
		// Test taken from the Spec 9.1.1
		$this->assertEquals(
			'a=1&c=hi%20there&f=25&f=50&f=a&z=p&z=t',
			Util::build_http_query(array('a'=>'1', 'c' =>'hi there', 'f'=>array(25, 50, 'a'), 'z'=>array('p','t')))
		);
		
		// From issue 164, by hidetaka
		// Based on discussion at 
		// http://groups.google.com/group/oauth/browse_thread/thread/7c698004be0d536/dced7b6c82b917b2?lnk=gst&q=sort#
		$this->assertEquals(
			'x=200&x=25&y=B&y=a',
			Util::build_http_query(array('x'=>array(25, 200), 'y'=>array('a', 'B')))
		);
	}
	
	public function testSplitHeader() {
		$this->assertEquals(
			array('oauth_foo'=>'bar','oauth_baz'=>'bla,rgh'),
			Util::split_header('OAuth realm="",oauth_foo=bar,oauth_baz="bla,rgh"')
		);
		$this->assertEquals(
			array(),
			Util::split_header('OAuth realm="",foo=bar,baz="bla,rgh"')
		);
		$this->assertEquals(
			array('foo'=>'bar', 'baz'=>'bla,rgh'),
			Util::split_header('OAuth realm="",foo=bar,baz="bla,rgh"', false)
		);
		$this->assertEquals(
			array('oauth_foo' => 'hi there'),
			Util::split_header('OAuth realm="",oauth_foo=hi+there,foo=bar,baz="bla,rgh"')
		);
		
	}

	public function testGetHeaders() {
		if (function_exists('apache_request_headers')) {
			$this->markTestSkipped('We assume the apache module is well tested. Since this module is present, no need testing our suplement');
		}
		
		$_SERVER['HTTP_HOST'] = 'foo';
		$_SERVER['HTTP_X_WHATEVER'] = 'bar';
		$this->assertEquals( array('Host'=>'foo', 'X-Whatever'=>'bar'), Util::get_headers() );
		
		// Test picking up the Content-Type of POST requests running as an Apache module but not having the ARH method
		$_SERVER['CONTENT_TYPE'] = 'application/x-www-form-urlencoded';
		$this->assertEquals( array('Host'=>'foo', 'X-Whatever'=>'bar', 'Content-Type'=>'application/x-www-form-urlencoded'), Util::get_headers() );
		
		// Test picking up the Content-Type of POST requests when using CGI
		unset($_SERVER['CONTENT_TYPE']);
		$this->assertEquals( array('Host'=>'foo', 'X-Whatever'=>'bar'), Util::get_headers() );
		$_ENV['CONTENT_TYPE'] = 'application/x-www-form-urlencoded';
		$this->assertEquals( array('Host'=>'foo', 'X-Whatever'=>'bar', 'Content-Type'=>'application/x-www-form-urlencoded'), Util::get_headers() );
	}
}
