<?php

namespace Bigfork\SilverStripeOAuth\Client\Extension;

use Bigfork\SilverStripeOAuth\Client\Model\Passport;
use SilverStripe\Core\Extension as SilverStripeExtension;

/**
 * Class MemberExtension
 * @package Bigfork\SilverStripeOAuth\Client\Extension
 * @param SilverStripe\Security\Member $owner
 */
class MemberExtension extends SilverStripeExtension
{
    /**
     * @var array
     */
    private static $db = [
        'OAuthSource' => 'Varchar(255)'
    ];

    /**
     * @var array
     */
    private static $has_many = [
        'Passports' => Passport::class
    ];

    /**
     * Remove this member's OAuth passports on delete
     */
    public function onBeforeDelete()
    {
        foreach($this->owner->Passports() as $passport){
            $passport->delete();
        }
    }
}
