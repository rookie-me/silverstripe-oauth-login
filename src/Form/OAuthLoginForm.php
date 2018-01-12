<?php

namespace Bigfork\SilverStripeOAuth\Client\Form;

use Bigfork\SilverStripeOAuth\Client\Authenticator\OAuthAuthenticator;
use Bigfork\SilverStripeOAuth\Client\Control\Controller;
use Bigfork\SilverStripeOAuth\Client\Helper\Helper;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\RequestHandler;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\Debug;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\HiddenField;
use SilverStripe\Security\MemberAuthenticator\MemberLoginForm;
use SilverStripe\Security\Security;
use function var_export;

class OAuthLoginForm extends MemberLoginForm
{
    /**
     * This field is used in the "You are logged in as %s" message
     * @var string
     */
    public $loggedInAsField = 'FirstName';

    /**
     * @var string
     */
    protected $authenticator_class = OAuthAuthenticator::class;

    /**
     * Required fields for validation
     *
     * @config
     * @var array
     */
    private static $required_fields = [];

    /**
     * @return string
     */
    public function getAuthenticatorName(){
        return _t('Bigfork\SilverStripeOAuth\Client\Form\LoginForm.TITLE', 'Social Sign-on');
    }

    /**
     * OAuthLoginForm constructor.
     *
     * @param RequestHandler $controller
     * @param string         $authenticatorClass
     * @param string         $name
     * @param null           $fields
     * @param null           $actions
     * @param bool           $checkCurrentUser
     */
    public function __construct( RequestHandler $controller, $authenticatorClass, $name, $fields = null, $actions = null, $checkCurrentUser = true ) { parent::__construct( $controller, $authenticatorClass, $name, $fields, $actions, $checkCurrentUser );
        $this->setAttribute("target", "oauthlogin"); // force an "open in new window" scenario
    }

    /**
     * @return FieldList
     */
    protected function getFormFields()
    {
        $request = $this->getRequest();
        if ($request->getVar('BackURL')) {
            $backURL = $request->getVar('BackURL');
        } else {
            $backURL = $request->getSession()->get('BackURL');
        }

        $fields = FieldList::create(
            HiddenField::create("AuthenticationMethod", null, $this->authenticator_class, $this)
        );

        if (isset($backURL)) {
            $fields->push(HiddenField::create('BackURL', 'BackURL', $backURL));
        }

        $this->extend('updateFields', $fields);

        return $fields;
    }

    /**
     * @return FieldList
     */
    protected function getFormActions()
    {
        $actions = FieldList::create();
        $providers = Config::inst()->get($this->authenticator_class, 'providers');

        foreach ($providers as $provider => $config) {
            $name = isset($config['name']) ? $config['name'] : $provider;
            $text = _t(
                'Bigfork\SilverStripeOAuth\Client\Form\LoginForm.BUTTON',
                'Sign in with {provider}',
                ['provider' => $name]
            );

            $action = FormAction::create('authenticate_' . $provider, $text)
                ->setTemplate("FormAction_OAuth_{$provider}");
            $actions->push($action);
        }

        $this->extend('updateActions', $actions);

        return $actions;
    }

    /**
     * {@inheritdoc}
     */
    public function hasMethod($method)
    {
        if (strpos($method, 'authenticate_') === 0) {
            $providers = Config::inst()->get($this->authenticator_class, 'providers');
            $name = substr($method, strlen('authenticate_'));

            if (isset($providers[$name])) {
                return true;
            }
        }

        return parent::hasMethod($method);
    }

    /**
     * {@inheritdoc}
     */
    public function __call($method, $args)
    {
        if (strpos($method, 'authenticate_') === 0) {
            $providers = Config::inst()->get($this->authenticator_class, 'providers');
            $name = substr($method, strlen('authenticate_'));

            if (isset($providers[$name])) {
                list($data) = $args;

                if (isset($data['BackURL'])) {
                    $request = Controller::curr()->getRequest();
                    $request->getSession()->set('BackURL', $data["BackURL"]);
                }

                $authenticator = Injector::inst()->create($this->authenticator_class);
                return $authenticator->handleProvider($name);
            }
        }

        return parent::__call($method, $args);
    }


}
