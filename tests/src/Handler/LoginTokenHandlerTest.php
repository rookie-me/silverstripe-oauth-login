<?php

namespace Bigfork\SilverStripeOAuth\Client\Test\Handler;

use Bigfork\SilverStripeOAuth\Client\Factory\MemberMapperFactory;
use Bigfork\SilverStripeOAuth\Client\Handler\LoginTokenHandler;
use Bigfork\SilverStripeOAuth\Client\Mapper\GenericMemberMapper;
use Bigfork\SilverStripeOAuth\Client\Test\LoginTestCase;
use Bigfork\SilverStripeOAuth\Client\Control\Controller;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use SilverStripe\Core\Injector\Injector;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;
use SilverStripe\Security\Member;
use ReflectionMethod;
use SilverStripe\Control\Session;
use SilverStripe\ORM\ValidationResult;

class LoginTokenHandlerTest extends LoginTestCase
{
    protected static $fixture_file = 'LoginTokenHandlerTest.yml';

    public function testHandleToken()
    {
        $mockAccessToken = $this->getConstructorlessMock(AccessToken::class);
        $mockProvider = $this->getConstructorlessMock(GenericProvider::class);

        $mockValidationResult = $this->getMock(ValidationResult::class, ['valid']);
        $mockValidationResult->expects($this->once())
            ->method('valid')
            ->will($this->returnValue(true));

        $mockMember = $this->getMock(Member::class, ['canLogIn', 'logIn']);
        $mockMember->expects($this->at(0))
            ->method('canLogIn')
            ->will($this->returnValue($mockValidationResult));
        $mockMember->expects($this->at(1))
            ->method('logIn');

        $mockHandler = $this->getMock(
            LoginTokenHandler::class,
            ['findOrCreateMember']
        );
        $mockHandler->expects($this->once())
            ->method('findOrCreateMember')
            ->with($mockAccessToken, $mockProvider)
            ->will($this->returnValue($mockMember));

        $mockHandler->handleToken($mockAccessToken, $mockProvider);
    }

    public function testAfterGetAccessTokenMemberCannotLogIn()
    {
        $mockAccessToken = $this->getConstructorlessMock(AccessToken::class);
        $mockProvider = $this->getConstructorlessMock(GenericProvider::class);

        $mockValidationResult = $this->getMock(ValidationResult::class, ['valid']);
        $mockValidationResult->expects($this->once())
            ->method('valid')
            ->will($this->returnValue(false));

        $mockMember = $this->getMock(Member::class, ['canLogIn', 'logIn']);
        $mockMember->expects($this->once())
            ->method('canLogIn')
            ->will($this->returnValue($mockValidationResult));

        $mockHandler = $this->getMock(LoginTokenHandler::class,
            ['findOrCreateMember']
        );
        $mockHandler->expects($this->once())
            ->method('findOrCreateMember')
            ->with($mockAccessToken, $mockProvider)
            ->will($this->returnValue($mockMember));

        $response = $mockHandler->handleToken($mockAccessToken, $mockProvider);
        $this->assertEquals(403, $response->getStatusCode());
    }

    public function testFindOrCreateMember()
    {
        $mockAccessToken = $this->getConstructorlessMock(AccessToken::class);

        $mockResourceOwner = $this->getConstructorlessMock(
            GenericResourceOwner::class,
            ['getId']
        );
        $mockResourceOwner->expects($this->exactly(2))
            ->method('getId')
            ->will($this->returnValue(123456789));

        $mockProvider = $this->getConstructorlessMock(
            GenericProvider::class,
            ['getResourceOwner']
        );
        $mockProvider->expects($this->once())
            ->method('getResourceOwner')
            ->with($mockAccessToken)
            ->will($this->returnValue($mockResourceOwner));

        $member = $this->objFromFixture(Member::class, 'member1');

        $mockHandler = $this->getMock(
            LoginTokenHandler::class,
            ['createMember']
        );
        $mockHandler->expects($this->once())
            ->method('createMember')
            ->with($mockAccessToken, $mockProvider)
            ->will($this->returnValue($member));

        $reflectionMethod = new ReflectionMethod(
            LoginTokenHandler::class,
            'findOrCreateMember'
        );
        $reflectionMethod->setAccessible(true);

        $this->assertEquals($member, $reflectionMethod->invoke($mockHandler, $mockAccessToken, $mockProvider));

        $passport = $member->Passports()->first();
        $this->assertNotNull($passport);
        $this->assertEquals(123456789, $passport->Identifier);
    }

    public function testCreateMember()
    {
        $mockAccessToken = $this->getConstructorlessMock(AccessToken::class);
        $mockResourceOwner = $this->getConstructorlessMock(GenericResourceOwner::class);

        $mockProvider = $this->getConstructorlessMock(
            GenericProvider::class,
            ['getResourceOwner']
        );
        $mockProvider->expects($this->once())
            ->method('getResourceOwner')
            ->with($mockAccessToken)
            ->will($this->returnValue($mockResourceOwner));

        $mockSession = $this->getConstructorlessMock(Session::class, ['inst_get']);
        $mockSession->expects($this->once())
            ->method('inst_get')
            ->with('oauth2.provider')
            ->will($this->returnValue('ProviderName'));

        $mockMemberMapper = $this->getConstructorlessMock(
            GenericMemberMapper::class,
            ['map']
        );
        $mockMemberMapper->expects($this->once())
            ->method('map')
            ->with($this->isInstanceOf('Member'), $mockResourceOwner)
            ->will($this->returnArgument(0));

        $mockHandler = $this->getConstructorlessMock(
            LoginTokenHandler::class,
            ['getSession', 'getMapper']
        );
        $mockHandler->expects($this->at(0))
            ->method('getSession')
            ->will($this->returnValue($mockSession));
        $mockHandler->expects($this->at(1))
            ->method('getMapper')
            ->with('ProviderName')
            ->will($this->returnValue($mockMemberMapper));

        $reflectionMethod = new ReflectionMethod(
            LoginTokenHandler::class,
            'createMember'
        );
        $reflectionMethod->setAccessible(true);

        $member = $reflectionMethod->invoke($mockHandler, $mockAccessToken, $mockProvider);
        $this->assertInstanceOf(Member::class, $member);
        $this->assertEquals('ProviderName', $member->OAuthSource);
    }

    public function testGetMapper()
    {
        // Store original
        $injector = Injector::inst();

        $mockMemberMapper = $this->getConstructorlessMock(
            GenericMemberMapper::class
        );

        $mockMapperFactory = $this->getMock(
            MemberMapperFactory::class,
            ['createMapper']
        );
        $mockMapperFactory->expects($this->once())
            ->method('createMapper')
            ->with('ProviderName')
            ->will($this->returnValue($mockMemberMapper));

        $mockInjector = $this->getMock('Injector', ['get']);
        $mockInjector->expects($this->once())
            ->method('get')
            ->with('MemberMapperFactory')
            ->will($this->returnValue($mockMapperFactory));

        Injector::set_inst($mockInjector);

        $handler = new LoginTokenHandler;
        $reflectionMethod = new ReflectionMethod(
            LoginTokenHandler::class,
            'getMapper'
        );
        $reflectionMethod->setAccessible(true);

        $this->assertEquals($mockMemberMapper, $reflectionMethod->invoke($handler, 'ProviderName'));

        // Restore things
        Injector::set_inst($injector);
    }
}
