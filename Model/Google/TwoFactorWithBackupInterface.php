<?php

namespace Scheb\TwoFactorBundle\Model\Google;

use Doctrine\Common\Collections\ArrayCollection;

interface TwoFactorWithBackupInterface extends TwoFactorInterface
{

    /**
     * Return the user's backup codes.
     *
     * @return \Doctrine\Common\Collections\ArrayCollection
     */
    public function getBackupCodes();

    /**
     * Set the user's backup codes.
     *
     * @param ArrayCollection $backupCodes
     */
    public function setBackupCodes(ArrayCollection $backupCodes);
}
