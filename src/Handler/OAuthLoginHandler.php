<?php

namespace Bigfork\SilverStripeOAuth\Client\Handler;

use Bigfork\SilverStripeOAuth\Client\Authenticator\OAuthAuthenticator;
use Bigfork\SilverStripeOAuth\Client\Control\Controller;
use Bigfork\SilverStripeOAuth\Client\Form\OAuthLoginForm;
use Exception;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\Debug;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\LoginHandler;
use SilverStripe\Security\MemberAuthenticator\MemberLoginForm;
use SilverStripe\Security\Security;

class OAuthLoginHandler extends LoginHandler
{

    private static $allowed_actions = [
        'login',
        'LoginForm',
        'authLogin'
    ];

    /**
     * @return null|OAuthLoginForm
     */
    public function loginForm()
    {
        // If we don't have any providers set up, quietly skip displaying OAuth Login
        if (!Config::inst()->get(OAuthAuthenticator::class, 'providers')) {
            return null;
        }

        return Injector::inst()->create( OAuthLoginForm::class, $this, OAuthAuthenticator::class, 'LoginForm');
    }

    /**
     * Login form handler method (equivalent of doLogin(), but as a result of a third-party redirect - not a form submit)
     *
     * This method is called when the user finishes the login flow on the OAuth Provider
     *
     * @param HTTPRequest $request
     * @return HTTPResponse
     */
    public function authLogin(HTTPRequest $request)
    {
        $failureMessage = null;
        $this->extend('beforeLogin');
        $session = $request->getSession();
        $backURL = $session->get('BackURL');

        /** @var ValidationResult $result */
        $member = $this->checkLogin([], $request, $result);

        // Successful login
        if ($member) {
            // $this->performLogin($member, [], $request); // this has already been handled by the LoginTokenHandler
            // Allow operations on the member after successful login
            $this->extend('afterLogin', $member);

            if ($member && $backURL) {
                $session->clear('BackURL');
            }
            return $this->redirectAfterSuccessfulLogin($backURL);
        }

        // Failed login
        $this->extend('failedLogin');

        $message = implode("; ", array_map(
            function ($message) {
                return $message['message'];
            },
            $result->getMessages()
        ));

        $form = $this->loginForm();
        $form->sessionMessage($message, 'bad');

        $suffix = ($backURL)?"?BackURL=".$backURL:"";

        // Fail to login redirects back to form (focus on this auth login type and remember the backurl, if present)
        return Controller::curr()->redirect($this->link().$suffix);
    }


    /**
     * Login in the user and figure out where to redirect the browser.
     *
     * The $data has this format
     * array(
     *   'AuthenticationMethod' => 'MemberAuthenticator',
     *   'Email' => 'sam@silverstripe.com',
     *   'Password' => '1nitialPassword',
     *   'BackURL' => 'test/link',
     *   [Optional: 'Remember' => 1 ]
     * )
     *
     * @return HTTPResponse
     */
    protected function redirectAfterSuccessfulLogin($overWriteBackURL = null)
    {
        $this
            ->getRequest()
            ->getSession()
            ->clear('SessionForms.MemberLoginForm.Email')
            ->clear('SessionForms.MemberLoginForm.Remember');

        $member = Security::getCurrentUser();

        // Absolute redirection URLs may cause spoofing
        $backURL = $this->getBackURL();

        // Overwrite BackURL from login flow
        if($overWriteBackURL && Director::is_site_url($overWriteBackURL)){
            $backURL = $overWriteBackURL;
        }

        if ($backURL) {
            return $this->redirect($backURL);
        }

        // If a default login dest has been set, redirect to that.
        $defaultLoginDest = Security::config()->get('default_login_dest');
        if ($defaultLoginDest) {
            return $this->redirect($defaultLoginDest);
        }

        // Redirect the user to the page where they came from
        if ($member) {
            // Welcome message
            $message = _t(
                'SilverStripe\\Security\\Member.WELCOMEBACK',
                'Welcome Back, {firstname}',
                ['firstname' => $member->{$this->loginForm()->loggedInAsField}]
            );
            Security::singleton()->setSessionMessage($message, ValidationResult::TYPE_GOOD);
        }

        // Redirect back
        return $this->redirectBack();
    }

}
