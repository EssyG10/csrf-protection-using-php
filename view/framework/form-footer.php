<?php
require_once __DIR__ . '/../../lib/SecurityService.php';
$antiCSRF = new \lib\securityService();
$antiCSRF->insertHiddenToken();
