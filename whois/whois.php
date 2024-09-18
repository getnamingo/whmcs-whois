<?php
if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}

function whois_config()
{
    return [
        'name' => 'WHOIS & RDAP Client',
        'description' => 'Provides WHOIS and RDAP query capabilities to retrieve domain registration details and status information',
        'version' => '1.0',
        'author' => 'Namingo',
        'fields' => [],
    ];
}

function whois_activate()
{
    return [
        'status' => 'success',
        'description' => 'WHOIS & RDAP Client activated successfully.',
    ];
}

function whois_deactivate()
{
    return [
        'status' => 'success',
        'description' => 'WHOIS & RDAP Client deactivated successfully.',
    ];
}

function whois_clientarea($vars)
{
    $templateFile = 'clientarea';
    $modulelink = $vars['modulelink'];
    $systemUrl = $vars['systemurl'];

    return [
        'pagetitle' => 'Domain Lookup',
        'breadcrumb' => ['index.php?m=whois' => 'Domain Lookup'],
        'templatefile' => $templateFile,
        'requirelogin' => false,
        'vars' => [
            'modulelink' => $modulelink,
            'systemurl' => $systemUrl,
        ],
    ];
}