# WHOIS & RDAP Client
Provides WHOIS and RDAP query capabilities to retrieve domain registration details and status information

## Installation

```bash
git clone https://github.com/getnamingo/whmcs-whois
mv whmcs-whois/whois /var/www/html/whmcs/modules/addons
chown -R www-data:www-data /var/www/html/whmcs/modules/addons/whois
chmod -R 755 /var/www/html/whmcs/modules/addons/whois
```

- Go to Settings > Apps & Integrations in the admin panel, search for "WHOIS & RDAP Client" and then activate "WHOIS & RDAP Client".

Edit the `/var/www/html/whmcs/modules/addons/whois/check.php` file and set your WHOIS and RDAP server URLs by replacing the placeholder values with your actual server addresses.

## Usage Instructions

The detailed usage instructions for this module are currently being written and will be available soon. This module is specifically designed to work with the Namingo Registrar project, ensuring WHOIS and RDAP client is provided to your customers. Please check back later for full documentation and guidance on using this module with your Namingo Registrar setup.

## License

Apache License 2.0