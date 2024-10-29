{block name="head"}
    <style>
        #bottom {
            display: none;
        }
        #result {
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        #whoisButton {
            margin-right: 0.5rem;
        }
    </style>
{/block}

<h1 class="mb-4">Domain Lookup</h1>

{block name="page-content"}
<div class="container">
    <div class="row">
        <div class="col-md-12">
            <div class="card mb-4">
                <div class="card-body">
                    <form id="lookupForm">
                        <div class="row mb-3">
                            <div class="col-12 col-md-8">
                                <input type="text" class="form-control form-control-lg" id="domainInput" placeholder="Enter Domain Name" autocapitalize="none">
                            </div>
                            <div class="col-12 col-md-4 mt-3 mt-md-0 d-flex flex-column flex-md-row justify-content-center justify-content-md-end text-center">
                                <button type="button" class="btn btn-info btn-lg mb-2 mb-md-0 w-100 w-md-auto me-md-2" id="whoisButton">WHOIS</button>
                                <button type="button" class="btn btn-info btn-lg mb-2 mb-md-0 w-100 w-md-auto" id="rdapButton">RDAP</button>
                            </div>
                        </div>
                    </form>
                    <div class="row" id="bottom">
                        <div class="col-lg-12">
                            <pre><code><div id="result"></div></code></pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    {literal}
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('domainInput').addEventListener('keypress', function(event) {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    document.getElementById('whoisButton').click();
                }
            });

            document.getElementById('whoisButton').addEventListener('click', function() {
                var domain = document.getElementById('domainInput').value.trim();
                if (!domain) {
                    alert('Please enter a domain name.');
                    return;
                }
                var captcha = '';

                fetch('/modules/addons/whois/check.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'domain=' + encodeURIComponent(domain) + '&captcha=' + encodeURIComponent(captcha) + '&type=whois'
                })
                .then(response => response.text())
                .then(data => {
                    document.getElementById('result').innerText = data;
                    document.getElementById('bottom').style.display = 'block';
                })
                .catch(error => console.error('Error:', error));
            });

            document.getElementById('rdapButton').addEventListener('click', function() {
                var domain = document.getElementById('domainInput').value.trim();
                if (!domain) {
                    alert('Please enter a domain name.');
                    return;
                }
                var captcha = '';

                fetch('/modules/addons/whois/check.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'domain=' + encodeURIComponent(domain) + '&captcha=' + encodeURIComponent(captcha) + '&type=rdap'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        console.error('Error:', data.error);
                        document.getElementById('result').innerText = 'Error: ' + data.error;
                    } else {
                        let output = parseRdapResponse(data);
                        document.getElementById('result').innerText = output;
                        document.getElementById('bottom').style.display = 'block';
                    }
                })
                .catch(error => console.error('Error:', error));
            });
        });

        function parseRdapResponse(data) {
            let output = '';

            // Domain Name and Status
            output += 'Domain Name: ' + (data.ldhName || 'N/A') + '\n';
            output += 'Status: ' + (data.status ? data.status.join(', ') : 'N/A') + '\n\n';

            // Parsing entities for specific roles like registrar and registrant
            if (data.entities && data.entities.length > 0) {
                data.entities.forEach(entity => {
                    if (entity.roles) {
                        output += entity.roles.join(', ').toUpperCase() + ' Contact:\n';
                        if (entity.vcardArray && entity.vcardArray.length > 1) {
                            output += parseVcard(entity.vcardArray[1]);
                        }
                        if (entity.roles.includes('registrar') && entity.publicIds) {
                            output += '   IANA ID: ' + entity.publicIds.map(id => id.identifier).join(', ') + '\n';
                        }
                        output += '\n';
                    }
                });
            }

            // Nameservers
            if (data.nameservers && data.nameservers.length > 0) {
                output += 'Nameservers:\n';
                data.nameservers.forEach(ns => {
                    output += ' - ' + ns.ldhName + '\n';
                });
                output += '\n';
            }

            // SecureDNS Details
            if (data.secureDNS) {
                output += 'SecureDNS:\n';
                output += ' - Delegation Signed: ' + (data.secureDNS.delegationSigned ? 'Yes' : 'No') + '\n';
                output += ' - Zone Signed: ' + (data.secureDNS.zoneSigned ? 'Yes' : 'No') + '\n\n';
            }

            // Events (like registration, expiration dates)
            if (data.events && data.events.length > 0) {
                output += 'Events:\n';
                data.events.forEach(event => {
                    output += ' - ' + event.eventAction + ': ' + new Date(event.eventDate).toLocaleString() + '\n';
                });
                output += '\n';
            }

            // Notices
            if (data.notices && data.notices.length > 0) {
                output += 'Notices:\n';
                data.notices.forEach(notice => {
                    output += ' - ' + (notice.title || 'Notice') + ': ' + notice.description.join(' ') + '\n';
                });
            }

            return output;
        }

        function parseVcard(vcard) {
            let vcardOutput = '';
            vcard.forEach(entry => {
                switch (entry[0]) {
                    case 'fn':
                        vcardOutput += '   Name: ' + entry[3] + '\n';
                        break;
                    case 'adr':
                        if (Array.isArray(entry[3]) && entry[3].length > 0) {
                            const addressParts = entry[3];
                            vcardOutput += '   Address: ' + addressParts.join(', ') + '\n';
                        }
                        break;
                    case 'email':
                        vcardOutput += '   Email: ' + entry[3] + '\n';
                        break;
                    case 'tel':
                        vcardOutput += '   Phone: ' + entry[3] + '\n';
                        break;
                }
            });
            return vcardOutput;
        }
    </script>
    {/literal}
</div>
{/block}
