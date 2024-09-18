## Document Contribution Request

**Type of Contribution:**
- [ ] New Threat Campaign / Group / Software

**Campaign/Group/Software Name:**
C0031 The Unitronics Defacement Campaign

**Description:**
The attack methodology used by this campaign can be outlined as follows:

MITRE TACTICS
STEPS INVOLVED

Initial Access
The CyberAv3ngers gang detected and took advantage of default credentials on numerous Unitronics PLC HMIs. A lot of these devices had "1111" as the default password. This first foothold allowed for additional actions, such as denial of service and manipulation. T0821 Default Password
Vulnerabilities linked to default credentials that permit unauthorized access to devices with unaltered default settings are identified as CVE-2017-11362.

Lateral Movement
CyberAv3ngers exploited linked gadgets that were available on the open internet. These included devices used to operate machinery and procedures in various industries, such as Unitronics Programmable Logic Controllers (PLCs) and Human-Machine Interfaces (HMIs). Additionally, they went after networking hardware, such as cellular modems, used in operational technology (OT) settings where many machines collaborate.

Inhibit Response
Controller HMIs were the target of the CyberAv3ngers. They interfered with the usual operation of several organizations' gadgets by defacing their interfaces. This implied that operators would be unable to efficiently monitor or manage their equipment. Furthermore, the assailants disrupted contact at a distant pumping station. This malfunction probably made it more difficult for the station to transmit or receive crucial data, which further impacted operations. All things considered, the campaign demonstrated how cyberattacks may seriously impair the ability of vital infrastructure to function.


**Source of Information:**
https://attack.mitre.org/campaigns/C0031/
https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a
https://www.controlglobal.com/blogs/unfettered/blog/33016371/why-is-cisa-not-addressing-the-plcs-in-the-unitronics-plc-attack
https://www.cisa.gov/sites/default/files/2023-12/aa23-335a-irgc-affiliated-cyber-actors-exploit-plcs-in-multiple-sectors-1.pdf

**Impact/Use Case:**

Impact
The CyberAv3ngers' Unitronics Defacement Campaign disrupted businesses by targeting Programmable Logic Controllers (PLCs) and Human-Machine Interfaces (HMIs), causing widespread operational halts across various industries. This attack demonstrated the significant impact of cyberattacks on critical infrastructure by rendering essential control systems unavailable. [T0826 Loss of Availability]

During the Unitronics Defacement Campaign, CyberAv3ngers disrupted operations in multiple industries by targeting Human-Machine Interfaces (HMIs) and Programmable Logic Controllers (PLCs). These attacks caused operational disruptions and highlighted vulnerabilities in interconnected industrial systems, leading to significant losses in productivity and revenue. [T0828 Loss of productivity and revenue]

CyberAv3ngers compromised Human-Machine Interfaces (HMIs) of Programmable Logic Controllers (PLCs) in the Unitronics Defacement Campaign by replacing standard graphics with their own, impeding operators’ ability to monitor and control operations. This attack highlighted the risks posed by vulnerabilities in industrial systems to safety and business continuity. [T0829 Loss of View]

**Additional Notes:**
Suspected IPs: 
178.162.227.180
185.162.235.206

DARC Managed Threat Hunting Queries :

01. Initial access i.e multiple login attempts from same srcip and default credentials brute force attack 
`stream=AUTHENTICATION where action='LOGIN' | duration 15m | select srcip, system, count_if(status='FAILED') as failcount, count_if(status='PASSED') as passcount | groupby srcip, system | having failcount >=50 and failcount >= passcount * 5`

02. DOS attack mitigating threat queries
`stream=firewall where srctype='PUBLIC' | duration 15m | select dstip, count(action) as totalcount, distinct_count(srcip) as distinctsrcip | groupby dstip | having distinctsrcip > 100 and totalcount > 20000`

03. Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls. Steps should be taken to periodically inventory internet-accessible devices to determine if they differ from the expected.
` _fetch * from event where $Stream=AUTHENTICATION AND $Duration=1d AND $AuthProto=VPN
group count_unique $Action, $SrcIP, $System, $User limit 20`



