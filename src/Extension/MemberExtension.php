<?php

namespace Bigfork\SilverStripeOAuth\Client\Extension;

use Bigfork\SilverStripeOAuth\Client\Model\OAuthPassport;
use SilverStripe\ORM\DataExtension;

class MemberExtension extends DataExtension
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
        'Passports' => OAuthPassport::class
    ];

    /**
     * Remove this member's OAuth passports on delete
     */
    public function onBeforeDelete()
    {
        $this->owner->Passports()->removeAll();
    }
}
