<?php
if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}

use WHMCS\Database\Capsule;

function whois_config()
{
    return [
        'name' => 'WHOIS & RDAP Client',
        'description' => 'Provides WHOIS and RDAP query capabilities to retrieve domain registration details and status information',
        'version' => '1.0',
        'author' => 'Namingo',
        'fields' => [
            'whoisServer' => [
                'FriendlyName' => 'WHOIS Server',
                'Type' => 'text',
                'Size' => '50',
                'Default' => 'whmcs.example.com',
                'Description' => 'Enter the WHOIS server hostname',
            ],
            'rdapServer' => [
                'FriendlyName' => 'RDAP Server',
                'Type' => 'text',
                'Size' => '50',
                'Default' => 'rdap.example.com',
                'Description' => 'Enter the RDAP server hostname',
            ],
            'contactLink' => [
                'FriendlyName' => 'Contact Form Link',
                'Type' => 'text',
                'Size' => '50',
                'Default' => '/index.php?m=contact&domain=', 
                'Description' => 'Enter the URL for the contact form link',
            ],
        ],
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
    $whoisServer = $vars['whoisServer'];
    $rdapServer = $vars['rdapServer'];
    $contactLink = $vars['contactLink'];

    return [
        'pagetitle' => 'Domain Lookup',
        'breadcrumb' => ['index.php?m=whois' => 'Domain Lookup'],
        'templatefile' => $templateFile,
        'requirelogin' => false,
        'vars' => [
            'modulelink' => $modulelink,
            'systemurl' => $systemUrl,
            'whoisServer' => $whoisServer,
            'rdapServer' => $rdapServer,
            'contactLink' => $contactLink,
        ],
    ];
}

// Action handler for WHOIS/RDAP check
if (isset($_GET['action']) && $_GET['action'] === 'check') {
    // Retrieve module configuration settings from the database
    $whoisServer = Capsule::table('tbladdonmodules')
        ->where('module', 'whois')
        ->where('setting', 'whoisServer')
        ->value('value');

    $rdapServer = Capsule::table('tbladdonmodules')
        ->where('module', 'whois')
        ->where('setting', 'rdapServer')
        ->value('value');

    $contactLink = Capsule::table('tbladdonmodules')
        ->where('module', 'whois')
        ->where('setting', 'contactLink')
        ->value('value');

    // Prepare parameters for the handler function
    $params = array_merge($_POST, [
        'whoisServer' => $whoisServer,
        'rdapServer' => $rdapServer,
        'contactLink' => $contactLink,
    ]);

    $output = whois_check_handler($params);
    header('Content-Type: application/json');
    echo $output;
    exit;
}

function whois_check_handler($params)
{
    $whoisServer = $params['whoisServer'];
    $rdapServer = 'https://' . $params['rdapServer'] . '/domain/';

    $domain = $_POST['domain'];
    $type = $_POST['type'];

    $sanitized_domain = filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);

    if (!$sanitized_domain) {
        return json_encode(['error' => 'Invalid domain.']);
    }

    if ($type === 'whois') {
        $output = '';
        $socket = fsockopen($whoisServer, 43, $errno, $errstr, 30);

        if (!$socket) {
            return json_encode(['error' => "Error fetching WHOIS data."]);
        }
        
        fwrite($socket, $domain . "\r\n");
        while (!feof($socket)) {
            $output .= fgets($socket);
        }
        fclose($socket);
    } elseif ($type === 'rdap') {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $rdapServer . $domain);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

        $output = curl_exec($ch);

        if (curl_errno($ch)) {
            curl_close($ch);
            return json_encode(['error' => 'cURL error: ' . curl_error($ch)]);
        }

        curl_close($ch);

        if (!$output) {
            return json_encode(['error' => 'Error fetching RDAP data.']);
        }
    }
    return $output;
}
