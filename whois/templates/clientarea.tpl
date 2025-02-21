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
                            <p id="contact"></p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Define dynamic links and URLs
            const moduleLink = "{$modulelink}";
            const contactLinkBase = "{$contactLink}";

            const domainInput = document.getElementById('domainInput');
            const errorMessage = document.getElementById('errorMessage');

            function validateInput() {
                const domain = domainInput.value.trim();
                const resultContainer = document.getElementById('result');
                const bottomContainer = document.getElementById('bottom');

                if (!domain) {
                    resultContainer.innerHTML = '<span style="color: #d9534f;">Please enter a valid domain name.</span>';
                    bottomContainer.style.display = 'block'; // Ensure the container is visible
                    domainInput.focus(); // Focus back on the input field
                    return false;
                }

                resultContainer.innerText = ''; // Clear previous messages
                bottomContainer.style.display = 'none'; // Hide the container
                return true;
            }

            // Function to update the contact link
            function updateContactLink(domain) {
                var contactElement = document.getElementById("contact");
                var contactLink = contactLinkBase + encodeURIComponent(domain);
                contactElement.innerHTML = '<a href="' + contactLink + '">Contact the domain registrant</a>';
            }
        
            document.getElementById('domainInput').addEventListener('keypress', function(event) {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    document.getElementById('whoisButton').click();
                }
            });

            document.getElementById('whoisButton').addEventListener('click', function() {
                if (!validateInput()) return;
                var domain = document.getElementById('domainInput').value.trim();
                var captcha = '';

                fetch(moduleLink + "&action=check", {
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
                    if (data.toLowerCase().includes(domain.toLowerCase())) {
                        updateContactLink(domain);
                    }
                })
                .catch(error => {
                    console.error('Error:', error); // Log the error to the console
                    document.getElementById('result').innerText = 'Error: ' + error.message; // Display the error message on the page
                });
            });

            document.getElementById('rdapButton').addEventListener('click', function() {
                if (!validateInput()) return;
                var domain = document.getElementById('domainInput').value.trim();
                var captcha = '';

                fetch(moduleLink + "&action=check", {
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
                        document.getElementById('bottom').style.display = 'block';
                    } else {
                        let output = parseRDAP(data);
                        document.getElementById('result').innerText = output;
                        document.getElementById('bottom').style.display = 'block';
                        if (output.toUpperCase().includes(domain.toUpperCase())) {
                            updateContactLink(domain);
                        }
                    }
                })
                .catch(error => {
                    console.error('Error:', error); // Log the error to the console
                    document.getElementById('result').innerText = 'Error: ' + error.message;
                    document.getElementById('bottom').style.display = 'block';
                });
            });
        });

        /**
         * Flattens the "entities" field.
         * The RDAP JSON sometimes nests arrays of entities.
         */
        function flattenEntities(entities) {
          let flat = [];
          entities.forEach(item => {
            if (Array.isArray(item)) {
              flat = flat.concat(item);
            } else if (typeof item === "object" && item !== null) {
              flat.push(item);
              // If an entity contains a nested entities array (for example, abuse contacts inside registrar)
              if (item.entities && Array.isArray(item.entities)) {
                flat = flat.concat(flattenEntities(item.entities));
              }
            }
          });
          return flat;
        }

        /**
         * Helper to extract a vCard field value by key from a vcardArray.
         */
        function getVCardValue(vcardArray, key) {
          if (!vcardArray || vcardArray.length < 2) return null;
          const props = vcardArray[1];
          const field = props.find(item => item[0] === key);
          return field ? field[3] : null;
        }

        /**
         * Main parser: Takes the RDAP JSON object and returns a WHOIS-style text output.
         */
        function parseRDAP(data) {
          let output = "";

          // Domain basic details
          output += `Domain Name: ${(data.ldhName || "N/A").toUpperCase()}\n`;
          output += `Domain ID: ${data.handle || "N/A"}\n\n`;

          // Domain status
          if (data.status && data.status.length) {
            output += "Status:\n";
            data.status.forEach(s => {
              output += `  - ${s}\n`;
            });
            output += "\n";
          }

          // Events (e.g., registration, expiration, last update)
          if (data.events && data.events.length) {
            output += "Events:\n";
            data.events.forEach(event => {
              // Capitalize event action for display
              const action = event.eventAction.charAt(0).toUpperCase() + event.eventAction.slice(1);
              output += `  ${action}: ${event.eventDate}\n`;
            });
            output += "\n";
          }

          // Nameservers
          if (data.nameservers && data.nameservers.length) {
            output += "Nameservers:\n";
            data.nameservers.forEach(ns => {
              output += `  - ${ns.ldhName || "N/A"}\n`;
            });
            output += "\n";
          }

          // Secure DNS info
          if (data.secureDNS) {
            output += "Secure DNS:\n";
            output += `  Zone Signed: ${data.secureDNS.zoneSigned}\n`;
            output += `  Delegation Signed: ${data.secureDNS.delegationSigned}\n\n`;
          }

          // Flatten all entities (registrar, registrant, admin, tech, billing, etc.)
          let allEntities = data.entities ? flattenEntities(data.entities) : [];

          // Registrar
          const registrar = allEntities.find(ent => ent.roles && ent.roles.includes("registrar"));
          if (registrar) {
            const regName = getVCardValue(registrar.vcardArray, "fn") || "N/A";
            output += `Registrar: ${regName}\n`;

            let ianaId = "";
            if (registrar.publicIds && Array.isArray(registrar.publicIds)) {
              const ianaObj = registrar.publicIds.find(pub => pub.type === "IANA Registrar ID");
              if (ianaObj) {
                ianaId = ianaObj.identifier;
              }
            }
            output += `IANA ID: ${ianaId}\n\n`;

            // Look for nested abuse contact within the registrar entity
            if (registrar.entities && Array.isArray(registrar.entities)) {
              const abuseContact = flattenEntities(registrar.entities).find(ent => ent.roles && ent.roles.includes("abuse"));
              if (abuseContact) {
                const abuseName = getVCardValue(abuseContact.vcardArray, "fn") || "N/A";
                const abuseEmail = getVCardValue(abuseContact.vcardArray, "email") || "N/A";
                const abuseTel = getVCardValue(abuseContact.vcardArray, "tel") || "N/A";
                output += "Registrar Abuse Contact:\n";
                output += `  Name: ${abuseName}\n`;
                output += `  Email: ${abuseEmail}\n`;
                output += `  Phone: ${abuseTel}\n`;
              }
            }
            output += "\n";
          }

          // Process other roles: registrant, admin, tech, billing
          const rolesToShow = ["registrant", "admin", "tech", "billing"];
          rolesToShow.forEach(role => {
            // Filter entities by role
            const ents = allEntities.filter(ent => ent.roles && ent.roles.includes(role));
            if (ents.length) {
              ents.forEach(ent => {
                const name = getVCardValue(ent.vcardArray, "fn") || "N/A";
                output += `${role.charAt(0).toUpperCase() + role.slice(1)} Contact: ${name}\n`;
                output += `  Handle: ${ent.handle || "N/A"}\n`;
                // Optionally, include organization and address if available
                const org = getVCardValue(ent.vcardArray, "org");
                if (org) {
                  output += `  Organization: ${org}\n`;
                }
                // You can add more fields as needed (e.g., email, phone)
                const email = getVCardValue(ent.vcardArray, "email");
                if (email) {
                  output += `  Email: ${email}\n`;
                }
                const tel = getVCardValue(ent.vcardArray, "tel");
                if (tel) {
                  output += `  Phone: ${tel}\n`;
                }
                const address = getVCardValue(ent.vcardArray, "adr");
                if (address) {
                  // Since the address is an array, filter out any empty parts and join them
                  const addrStr = Array.isArray(address) ? address.filter(part => part && part.trim()).join(', ') : address;
                  output += `  Address: ${addrStr}\n`;
                }
                output += "\n";
              });
            }
          });

          // Notices
          if (data.notices && data.notices.length) {
            output += "Notices:\n";
            data.notices.forEach(notice => {
              if (notice.title) {
                output += `  ${notice.title}\n`;
              }
              if (notice.description && Array.isArray(notice.description)) {
                notice.description.forEach(desc => {
                  output += `    ${desc}\n`;
                });
              }
              output += "\n";
            });
          }

          return output;
        }
    </script>
</div>
{/block}
