<?php

namespace Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Google;

use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorProviderInterface;
use Symfony\Bundle\FrameworkBundle\Templating\EngineInterface;
use Scheb\TwoFactorBundle\Model\Google\TwoFactorInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Scheb\TwoFactorBundle\Security\TwoFactor\AuthenticationContext;
use Doctrine\ORM\EntityManager;
use Symfony\Component\Security\Core\Util\StringUtils;

class TwoFactorProvider implements TwoFactorProviderInterface
{

    /**
     * @var \Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Google\GoogleAuthenticator $authenticator
     */
    private $authenticator;

    /**
     * @var \Doctrine\ORM\EntityManager
     */
    private $em;

    /**
     * @var \Symfony\Bundle\FrameworkBundle\Templating\EngineInterface $templating
     */
    private $templating;

    /**
     * @var string $formTemplate
     */
    private $formTemplate;

    /**
     * @var boolean $useBackupCodes
     */
    private $useBackupCodes;

    /**
     * @var string $authCodeParameter
     */
    private $authCodeParameter;

    /**
     * Construct provider for Google authentication
     *
     * @param \Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Google\GoogleAuthenticator $authenticator
     * @param \Doctrine\ORM\EntityManager                                                   $em
     * @param \Symfony\Bundle\FrameworkBundle\Templating\EngineInterface                    $templating
     * @param string                                                                        $formTemplate
     * @param boolean                                                                       $useBackupCodes
     * @param string                                                                        $authCodeParameter
     */
    public function __construct(GoogleAuthenticator $authenticator,
                                EntityManager $em, EngineInterface $templating,
                                $formTemplate, $useBackupCodes,
                                $authCodeParameter)
    {
        $this->authenticator = $authenticator;
        $this->em = $em;
        $this->templating = $templating;
        $this->formTemplate = $formTemplate;
        $this->useBackupCodes = $useBackupCodes;
        $this->authCodeParameter = $authCodeParameter;
    }

    /**
     * Begin Google authentication process
     *
     * @param  \Scheb\TwoFactorBundle\Security\TwoFactor\AuthenticationContext $context
     * @return boolean
     */
    public function beginAuthentication(AuthenticationContext $context)
    {
        // Check if user can do email authentication
        $user = $context->getUser();

        return $user instanceof TwoFactorInterface && $user->getGoogleAuthenticatorSecret();
    }

    /**
     * Ask for Google authentication code
     *
     * @param  \Scheb\TwoFactorBundle\Security\TwoFactor\AuthenticationContext $context
     * @return \Symfony\Component\HttpFoundation\Response|null
     */
    public function requestAuthenticationCode(AuthenticationContext $context)
    {
        $user = $context->getUser();
        $request = $context->getRequest();
        $session = $context->getSession();

        // Display and process form
        if ($request->getMethod() == 'POST') {
            $authCode = $request->get($this->authCodeParameter);
            $validCode = $this->authenticator->checkCode($user, $authCode) == true;
            if ($validCode || $this->checkBackupCode($context, $authCode)) {
                $context->setAuthenticated(true);

                return new RedirectResponse($request->getUri());
            } else {
                $session->getFlashBag()->set("two_factor",
                                             "scheb_two_factor.code_invalid");
            }
        }

        // Force authentication code dialog
        return $this->templating->renderResponse($this->formTemplate,
                                                 array(
                'useTrustedOption' => $context->useTrustedOption()
        ));
    }

    protected function checkBackupCode(AuthenticationContext $context, $authCode)
    {
        if (!$this->useBackupCodes) {
            return false;
        }

        $user = $context->getUser();
        $backupCodes = $user->getBackupCodes();

        foreach ($backupCodes as $backupCode) {
            if ($backupCode->getUsed()) {
                continue;
            }
            if (StringUtils::equals($backupCode->getCode(), $authCode)) {
                $backupCode->setUsed(true);
                $this->em->flush($backupCode);
                return true;
            }
        }
        return false;
    }

}
