<?php

namespace Bigfork\SilverStripeOAuth\Client\Authenticator;

use Bigfork\SilverStripeOAuth\Client\Control\Controller;
use Bigfork\SilverStripeOAuth\Client\Handler\OAuthLoginHandler;
use Bigfork\SilverStripeOAuth\Client\Helper\Helper;
use Exception;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Config;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

class OAuthAuthenticator extends MemberAuthenticator
{

    /**
     * @var array
     */
    private static $providers = [];

    /**
     * Returns the services supported by this authenticator
     *
     * @return int
     */
    public function supportedServices()
    {
        return Authenticator::LOGIN | Authenticator::LOGOUT;
    }

    /**
     * Handle a submission for a given provider - build redirection
     *
     * @param string $name
     * @return HTTPResponse
     */
    public function handleProvider($name)
    {
        $this->extend('onBeforeHandleProvider', $name);

        $providers = Config::inst()->get(self::class, 'providers');
        $config = $providers[$name];
        $scope = isset($config['scopes']) ? $config['scopes'] : ['email']; // We need at least an email address!
        $url = Helper::buildAuthorisationUrl($name, 'login', $scope);

        $controller = Controller::curr();
        return $controller->redirect($url);
    }

    /**
     * Method to authenticate an user.
     *
     * @param array            $data   Raw data to authenticate the user.
     * @param HTTPRequest      $request
     * @param ValidationResult $result A validationresult which is either valid or contains the error message(s)
     *
     * @return Member The matched member, or null if the authentication fails
     */
    public function authenticate( array $data = [], HTTPRequest $request, ValidationResult &$result = null )
    {
        // Find authenticated member
        $member = $this->authenticateOAuth($request, $result);

        // Optionally record every login attempt as a {@link LoginAttempt} object
        $this->recordLoginAttempt($data, $request, $member, $result->isValid());

        return $result->isValid() ? $member : null;
    }

    /**
     * Attempt to find and authenticate member if possible from the given data (equivalent of authenticateMember)
     *
     * @param HTTPRequest $request HTTPRequest from OAuth response
     * @param ValidationResult|null $result
     * @param Member|null $member This third parameter is used in the CMSAuthenticator(s)
     * @return null|Member Found member, only if successful login
     */
    protected function authenticateOAuth(HTTPRequest $request, ValidationResult &$result = null, Member $member = null)
    {
        $preErrorRequest = $request;
        $result = $result ?: ValidationResult::create();

        // this should run the request through the oauth controller
        try {
            $controller = Controller::create();
            $controller->setRequest($request);
            $controller->callback($request);    // this is the equivalent of performLogin(), it also checks validateCanLogin() on LoginTokenHandler
            $member = Security::getCurrentUser();

            // Optionally record every login attempt as a {@link LoginAttempt} object
            $this->recordLoginAttempt([], $request, $member, true);

            // Keep track of successful logins, too
            $member->registerSuccessfulLogin();

        }catch(Exception $e){
            // @todo - fix this hackiness - We may have set some errors in the headers if our Controller::callback() was unsuccessful
            Controller::curr()->setRequest($preErrorRequest);

            // Optionally record every login attempt as a {@link LoginAttempt} object
            $this->recordLoginAttempt([], $request, $member, false);

            // Add an error to the results
            $result->addError( $e->getMessage() );
        }

        return $member;
    }


    /**
     * @param string $link
     * @return OAuthLoginHandler
     */
    public function getLoginHandler($link)
    {
        return OAuthLoginHandler::create($link, $this);
    }
}
