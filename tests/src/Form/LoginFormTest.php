<?php

namespace Bigfork\SilverStripeOAuth\Client\Test\Form;

use Bigfork\SilverStripeOAuth\Client\Authenticator\OAuthAuthenticator;
use Bigfork\SilverStripeOAuth\Client\Form\OAuthLoginForm;
use Bigfork\SilverStripeOAuth\Client\Test\LoginTestCase;
use Bigfork\SilverStripeOAuth\Client\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\FormAction;

class LoginFormTest extends LoginTestCase
{
    public function testGetActions()
    {
        $providers = [
            'ProviderOne' => [
                'scopes' => ['email']
            ],
            'ProviderTwo' => [
                'name' => 'Custom Name',
                'scopes' => ['email']
            ]
        ];

        Config::inst()->remove(OAuthAuthenticator::class, 'providers');
        Config::inst()->update(OAuthAuthenticator::class, 'providers', $providers);

        $form = new OAuthLoginForm(new Controller, '', 'FormName');
        $actions = $form->getActions();

        $this->assertInstanceOf(FieldList::class, $actions);
        $this->assertEquals(2, $actions->count());

        $first = $actions->first();
        $this->assertInstanceOf(FormAction::class, $first);
        $this->assertEquals('authenticate_ProviderOne', $first->actionName());

        $last = $actions->last();
        $this->assertInstanceOf(FormAction::class, $last);
        $this->assertEquals('authenticate_ProviderTwo', $last->actionName());
        $this->assertContains('Custom Name', $last->Title());
    }

    public function testHandleProvider()
    {
        $providers = [
            'ProviderName' => []
        ];

        Config::inst()->remove(OAuthAuthenticator::class, 'providers');
        Config::inst()->update(OAuthAuthenticator::class, 'providers', $providers);

        $controller = new LoginFormTest_Controller;
        Injector::inst()->registerService($controller, Controller::class);

        $expectedUrl = Director::absoluteBaseURL() . 'loginformtest/authenticate/';
        $expectedUrl .= '?provider=ProviderName&context=login&scope%5B0%5D=email';

        $expectedResponse = new HTTPResponse();

        $mockController = $this->getMock(Controller::class, ['redirect']);
        $mockController->expects($this->once())
            ->method('redirect')
            ->with($expectedUrl)
            ->will($this->returnValue($expectedResponse));

        $mockLoginForm = $this->getConstructorlessMock(
            OAuthLoginForm::class,
            ['getController']
        );
        $mockLoginForm->expects($this->once())
            ->method('getController')
            ->will($this->returnValue($mockController));

        $response = $mockLoginForm->handleProvider('ProviderName');
        $this->assertSame($response, $expectedResponse);
    }

    public function testMagicCallers()
    {
        $providers = [
            'ProviderName' => []
        ];

        Config::inst()->remove(OAuthAuthenticator::class, 'providers');
        Config::inst()->update(OAuthAuthenticator::class, 'providers', $providers);

        $expectedResponse = new HTTPResponse();

        $mockLoginForm = $this->getConstructorlessMock(
            OAuthLoginForm::class,
            ['handleProvider']
        );
        $mockLoginForm->expects($this->once())
            ->method('handleProvider')
            ->with('ProviderName')
            ->will($this->returnValue($expectedResponse));

        $response = $mockLoginForm->authenticate_ProviderName();
        $this->assertSame($response, $expectedResponse);
    }
}

class LoginFormTest_Controller extends Controller
{
    public function Link()
    {
        return 'loginformtest/';
    }

    public function AbsoluteLink()
    {
        return 'http://mysite.com/loginformtest/';
    }
}
