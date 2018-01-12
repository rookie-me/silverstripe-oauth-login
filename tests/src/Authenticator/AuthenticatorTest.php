<?php

namespace Bigfork\SilverStripeOAuth\Client\Test\Authenticator;

use Bigfork\SilverStripeOAuth\Client\Authenticator\OAuthAuthenticator;
use Bigfork\SilverStripeOAuth\Client\Form\OAuthLoginForm;
use Bigfork\SilverStripeOAuth\Client\Test\LoginTestCase;
use Bigfork\SilverStripeOAuth\Client\Control\Controller;
use SilverStripe\Core\Config\Config;

class AuthenticatorTest extends LoginTestCase
{
    public function testGetLoginForm()
    {
        Config::inst()->remove(OAuthAuthenticator::class, 'providers');
        $controller = new Controller;
        $form = OAuthAuthenticator::get_login_form($controller);

        $this->assertNull($form, 'get_login_form should return null if no providers have been set up');

        $providers = [
            'ProviderOne' => [
                'scopes' => ['email']
            ]
        ];
        Config::inst()->update(OAuthAuthenticator::class, 'providers', $providers);

        $form = OAuthAuthenticator::get_login_form($controller);
        $this->assertInstanceOf( OAuthLoginForm::class, $form);
        $this->assertEquals('LoginForm', $form->getName());
    }
}
