<?php

namespace Scheb\TwoFactorBundle\Model\Google;

interface BackupCodeInterface
{

    /**
     * @return boolean true if the Backup Code has been used.
     */
    public function getUsed();

    /**
     * Mark the Backup Code as used.
     *
     * @param boolean $used
     */
    public function setUsed($used);

    /**
     * Get the Backup Code
     *
     * @return string
     */
    public function getCode();
}
