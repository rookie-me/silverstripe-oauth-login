<?php

namespace Bigfork\SilverStripeOAuth\Client\Test\Factory;

use Bigfork\SilverStripeOAuth\Client\Factory\MemberMapperFactory;
use Bigfork\SilverStripeOAuth\Client\Mapper\GenericMemberMapper;
use Bigfork\SilverStripeOAuth\Client\Mapper\MemberMapperInterface;
use Bigfork\SilverStripeOAuth\Client\Test\LoginTestCase;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Member;

class MemberMapperFactoryTest extends LoginTestCase
{
    public function testCreateMapper()
    {
        Config::inst()->update(
            MemberMapperFactory::class,
            'mappers',
            ['TestProvider' => MemberMapperFactoryTest_Mapper::class]
        );

        $factory = new MemberMapperFactory();
        $this->assertInstanceOf(
            MemberMapperFactoryTest_Mapper::class,
            $factory->createMapper('TestProvider')
        );

        // Store original
        $injector = Injector::inst();

        $genericMapper = new GenericMemberMapper('test');

        $mockInjector = $this->getMock(Injector::class, ['createWithArgs']);
        $mockInjector->expects($this->once())
            ->method('createWithArgs')
            ->with(GenericMemberMapper::class, ['AnotherTestProvider'])
            ->will($this->returnValue($genericMapper));

        Injector::set_inst($mockInjector);

        $this->assertSame($genericMapper, $factory->createMapper('AnotherTestProvider'));

        // Restore things
        Injector::set_inst($injector);
    }
}

class MemberMapperFactoryTest_Mapper implements MemberMapperInterface
{
    public function map(Member $member, ResourceOwnerInterface $resourceOwner)
    {
        return $member;
    }
}
