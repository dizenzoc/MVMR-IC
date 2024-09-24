import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Component, ElementRef, OnInit, ViewChild } from '@angular/core';
import { NgForm } from '@angular/forms';
import { Router } from '@angular/router';
import { FileXML } from 'src/app/interface/fileXML';
import { MainService } from 'src/app/service/main.service';
import { ThemePalette } from '@angular/material/core';
import { ProgressBarMode } from '@angular/material/progress-bar';
import { Filesystem, Directory, Encoding } from '@capacitor/filesystem';
import { Share } from '@capacitor/share';
import { Capacitor } from '@capacitor/core';
import jsPDF from 'jspdf';
import html2pdf from 'html2pdf.js'
import html2canvas from 'html2canvas';
import { ToastController } from '@ionic/angular';
import { timeout } from 'rxjs';
import { faL } from '@fortawesome/free-solid-svg-icons';
import { Platform } from '@ionic/angular';


@Component({
    selector: 'app-homepage',
    templateUrl: './homepage.component.html',
    styleUrls: ['./homepage.component.css']
})
export class HomepageComponent implements OnInit {

    files: Map<string, FileXML>  //Map <nome, files> degli XML che si vogliono caricare sul server
    xmls: FileXML[] = []

    devgrid_columns: string[] = ['host', 'service', 'date'] //campi del report dev-grid

    //status
    status = 0; //man mano che vengono eseguite le tre fasi (merging, harvesting, bayesian) lo status viene incrementato

    //PROGRESS BAR
    color: ThemePalette = 'primary';
    mode: ProgressBarMode = 'buffer';
    value = 0;
    bufferValue = 0;

    // Variabili per la seconda progress bar (PDF export)
    isExportingPdf = false;
    pdfStatus = 0;
    pdfColor: ThemePalette = 'primary';
    pdfMode: ProgressBarMode = 'buffer';
    pdfValue = 0;
    pdfBufferValue = 0; //prima era 100

    //SEARCH FOR VULNERABILITIES BUTTON CHECK
    flag_vuln_button_clicked: boolean = false; //fin quando non viene caricato un file il pulsante non viene mostrato (si aggiorna in sendXMLs2Server() quando viene cliccato il pulsante)

    //Flag per i file selezionati
    flag_nmap: boolean = false;
    flag_openvas: boolean = false;
    flag_nessus: boolean = false;
    flag_owaspzap: boolean = false;

    //Flag per mostrare i risultati della scansione
    flag_show_report: boolean = false; //inizialmente non ci sono risultati quindi il report viene nascosto (si aggiorna in sendXMLs2Server() quando si ottengono i risultati finali)

    //Summary JSON per ogni file XML caricato sul server
    nmap_summary: any;
    openvas_summary: any;
    owaspzap_summary: any;
    nessus_summary: any;
    merge_summary: any;

    dataFromMock: any = []

    final_summary: any = {}
    hosts: any = []
    severity: any = []

    constructor(protected mainService: MainService, protected http: HttpClient, private router: Router, private toastController: ToastController, private platform:Platform) {
        this.files = new Map()  //costruttore Map

        this.final_summary = {
            "date": "2022-10-28T08:28:00.346Z",
            "vulnerabilities": {
                "192.168.81.131": {
                    "21/ftp": {
                        "high": {
                            "Gain Privileges": [
                                {
                                    "id": 777,
                                    "host": "192.168.81.131",
                                    "service": "21/ftp",
                                    "description": "Each Unix or Unix-like system has several default username/password combinations. In one default combination, the login is \"4DGifts\" and the password is \"4DGifts\" or no password.\n\nA Unix account has a guessable password.\n\nIt was possible to login with the following credentials <User>:<Password>\n\nmsfadmin:msfadmin\npostgres:postgres\nservice:service\nuser:user\n",
                                    "cvss": "7.5 High AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                    "solution": "If the account is not needed, disable or delete the account from the system.\nIf the account is required, change the default login and password to a value that is difficult to guess.. Maggiori info (https://exchange.xforce.ibmcloud.com/vulnerabilities/CVE-1999-0501)\n\nChange the password as soon as possible.",
                                    "risk": "FTP Brute Force Logins Reporting",
                                    "type": "Gain Privileges",
                                    "id_cve": [
                                        "CVE-1999-0501"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ]
                        },
                        "medium": {
                            "Information Disclosure": [
                                {
                                    "id": 778,
                                    "host": "192.168.81.131",
                                    "service": "21/ftp",
                                    "description": "The remote FTP service accepts logins without a previous sent 'AUTH TLS' command. Response(s):\n\nNon-anonymous sessions: 331 Password required for openvasvt\nAnonymous sessions:     331 Password required for anonymous\n",
                                    "cvss": "4.8 Medium AV:A/AC:L/Au:N/C:P/I:P/A:N",
                                    "solution": "Enable FTPS or enforce the connection via the 'AUTH TLS' command. Please see\n  the manual of the FTP service for more information.",
                                    "risk": "FTP Unencrypted Cleartext Login",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        },
                        "unknown": {
                            "Information Disclosure": [
                                {
                                    "id": 779,
                                    "host": "192.168.81.131",
                                    "service": "21/ftp",
                                    "description": "Security patches may have been 'backported' to the remote FTP server without changing its version number. \n\nBanner-based checks have been disabled to avoid false positives. \n\nNote that this test is informational only and does not denote any security problem. Security patches are backported.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Backported Security Patch Detection (FTP)",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://access.redhat.com/security/updates/backporting/?sc_cid=3093"
                                    ]
                                },
                                {
                                    "id": 780,
                                    "host": "192.168.81.131",
                                    "service": "21/ftp",
                                    "description": "It is possible to obtain the banner of the remote FTP server by connecting to a remote port. An FTP server is listening on a remote port.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "FTP Server Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 782,
                                    "host": "192.168.81.131",
                                    "service": "21/ftp",
                                    "description": "This plugin is a SYN 'half-open' port scanner.  It shall be reasonably quick even against a firewalled target. \n\nNote that SYN scans are less intrusive than TCP (full connect) scans against broken services, but they might cause problems for less robust firewalls and also leave unclosed connections on the remote target, if the network is loaded. It is possible to determine which TCP ports are open.",
                                    "cvss": "unknown",
                                    "solution": "Protect your target with an IP filter.",
                                    "risk": "Nessus SYN scanner",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Denial of Service (DoS)": [
                                {
                                    "id": 781,
                                    "host": "192.168.81.131",
                                    "service": "21/ftp",
                                    "description": "Nessus was able to identify the remote service by its banner or by looking at the error message it sends when it receives an HTTP request. The remote service could be identified.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Service Detection",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "File Inclusion": [
                                {
                                    "id": 776,
                                    "host": "192.168.81.131",
                                    "service": "21/ftp",
                                    "description": "unknown",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "unknown",
                                    "type": "File Inclusion",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        }
                    },
                    "22/ssh": {
                        "critical": {
                            "Gain Privileges": [
                                {
                                    "id": 798,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "The remote SSH host key has been generated on a Debian or Ubuntu system which contains a bug in the random number generator of its OpenSSL library.\n\nThe problem is due to a Debian packager removing nearly all sources of entropy in the remote version of OpenSSL.\n\nAn attacker can easily obtain the private part of the remote key and use this to set up decipher the remote session  or set up a man in the middle attack. The remote SSH host keys are weak.",
                                    "cvss": "10.0 High CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Consider all cryptographic material generated on the remote host to be guessable. In particuliar, all SSH, SSL and OpenVPN key material should be re-generated.",
                                    "risk": "Debian OpenSSH/OpenSSL Package Random Number Generator Weakness",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.nessus.org/u?107f9bdc",
                                        "http://www.nessus.org/u?f14f4224"
                                    ]
                                }
                            ]
                        },
                        "high": {
                            "Gain Privileges": [
                                {
                                    "id": 784,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "Each Unix or Unix-like system has several default username/password combinations. In one default combination, the login is \"4DGifts\" and the password is \"4DGifts\" or no password.\n\nA Unix account has a guessable password.\n\nIt was possible to login with the following credentials <User>:<Password>\n\nmsfadmin:msfadmin\npostgres:postgres\nservice:service\nuser:user\n\n",
                                    "cvss": "7.5 High AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                    "solution": "If the account is not needed, disable or delete the account from the system.\nIf the account is required, change the default login and password to a value that is difficult to guess.. Maggiori info (https://exchange.xforce.ibmcloud.com/vulnerabilities/CVE-1999-0501)\n\nChange the password as soon as possible.",
                                    "risk": "SSH Brute Force Logins With Default Credentials Reporting",
                                    "type": "Gain Privileges",
                                    "id_cve": [
                                        "CVE-1999-0501"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ]
                        },
                        "medium": {
                            "Gain Privileges": [
                                {
                                    "id": 785,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "The remote SSH server supports the following weak KEX algorithm(s):\n\nKEX algorithm                      | Reason\n-------------------------------------------------------------------------------------------\ndiffie-hellman-group-exchange-sha1 | Using SHA-1\ndiffie-hellman-group1-sha1         | Using Oakley Group 2 (a 1024-bit MODP group) and SHA-1\n",
                                    "cvss": "5.3 Medium CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "solution": "Disable the reported weak KEX algorithm(s)\n\n  - 1024-bit MODP group / prime KEX algorithms:\n\n  Alternatively use elliptic-curve Diffie-Hellmann in general, e.g. Curve 25519.",
                                    "risk": "Weak Key Exchange (KEX) Algorithm(s) Supported (SSH)",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "https://weakdh.org/sysadmin.html"
                                    ]
                                },
                                {
                                    "id": 796,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "Nessus has detected that the remote SSH server is configured to use the Arcfour stream cipher or no cipher at all. RFC 4253 advises against using Arcfour due to an issue with weak keys. The remote SSH server is configured to allow weak encryption algorithms or no algorithm at all.",
                                    "cvss": "4.3 Medium CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "solution": "Contact the vendor or consult product documentation to remove the weak ciphers.",
                                    "risk": "SSH Weak Algorithms Supported",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "https://tools.ietf.org/html/rfc4253#section-6.3"
                                    ]
                                }
                            ],
                            "Information Disclosure": [
                                {
                                    "id": 786,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "The remote SSH server supports the following weak host key algorithm(s):\n\nhost key algorithm | Description\n-----------------------------------------------------------------------------------------\nssh-dss            | Digital Signature Algorithm (DSA) / Digital Signature Standard (DSS)\n",
                                    "cvss": "5.3 Medium CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "solution": "Disable the reported weak host key algorithm(s).",
                                    "risk": "Weak Host Key Algorithm(s) (SSH)",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Denial of Service (DoS)": [
                                {
                                    "id": 787,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "The remote SSH server supports the following weak client-to-server encryption algorithm(s):\n\n3des-cbc\naes128-cbc\naes192-cbc\naes256-cbc\narcfour\narcfour128\narcfour256\nblowfish-cbc\ncast128-cbc\nrijndael-cbc@lysator.liu.se\n\n\nThe remote SSH server supports the following weak server-to-client encryption algorithm(s):\n\n3des-cbc\naes128-cbc\naes192-cbc\naes256-cbc\narcfour\narcfour128\narcfour256\nblowfish-cbc\ncast128-cbc\nrijndael-cbc@lysator.liu.se\n",
                                    "cvss": "4.3 Medium AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "solution": "Disable the reported weak encryption algorithm(s).",
                                    "risk": "Weak Encryption Algorithm(s) Supported (SSH)",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "https://tools.ietf.org/html/rfc4253#section-6.3"
                                    ]
                                }
                            ]
                        },
                        "low": {
                            "Gain Privileges": [
                                {
                                    "id": 785,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "The remote SSH server supports the following weak KEX algorithm(s):\n\nKEX algorithm                      | Reason\n-------------------------------------------------------------------------------------------\ndiffie-hellman-group-exchange-sha1 | Using SHA-1\ndiffie-hellman-group1-sha1         | Using Oakley Group 2 (a 1024-bit MODP group) and SHA-1\n",
                                    "cvss": "5.3 Medium CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "solution": "Disable the reported weak KEX algorithm(s)\n\n  - 1024-bit MODP group / prime KEX algorithms:\n\n  Alternatively use elliptic-curve Diffie-Hellmann in general, e.g. Curve 25519.",
                                    "risk": "Weak Key Exchange (KEX) Algorithm(s) Supported (SSH)",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "https://weakdh.org/sysadmin.html"
                                    ]
                                }
                            ],
                            "Information Disclosure": [
                                {
                                    "id": 786,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "The remote SSH server supports the following weak host key algorithm(s):\n\nhost key algorithm | Description\n-----------------------------------------------------------------------------------------\nssh-dss            | Digital Signature Algorithm (DSA) / Digital Signature Standard (DSS)\n",
                                    "cvss": "5.3 Medium CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "solution": "Disable the reported weak host key algorithm(s).",
                                    "risk": "Weak Host Key Algorithm(s) (SSH)",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 792,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "The SSH server is configured to support Cipher Block Chaining (CBC) encryption.  This may allow an attacker to recover the plaintext message from the ciphertext. \n\nNote that this plugin only checks for the options of the SSH server and does not check for vulnerable software versions. The SSH server is configured to use Cipher Block Chaining.",
                                    "cvss": "2.6 Low CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N",
                                    "solution": "Contact the vendor or consult product documentation to disable CBC mode cipher encryption, and enable CTR or GCM cipher mode encryption.",
                                    "risk": "SSH Server CBC Mode Ciphers Enabled",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 794,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "The remote SSH server is configured to allow either MD5 or 96-bit MAC algorithms, both of which are considered weak.\n\nNote that this plugin only checks for the options of the SSH server, and it does not check for vulnerable software versions. The remote SSH server is configured to allow MD5 and 96-bit MAC algorithms.",
                                    "cvss": "2.6 Low CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N",
                                    "solution": "Contact the vendor or consult product documentation to disable MD5 and 96-bit MAC algorithms.",
                                    "risk": "SSH Weak MAC Algorithms Enabled",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 795,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "The remote SSH server is configured to allow key exchange algorithms which are considered weak.\n\nThis is based on the IETF draft document Key Exchange (KEX) Method Updates and Recommendations for Secure Shell (SSH) draft-ietf-curdle-ssh-kex-sha2-20. Section 4 lists guidance on key exchange algorithms that SHOULD NOT and MUST NOT be enabled. This includes:\n\n  diffie-hellman-group-exchange-sha1\n\n  diffie-hellman-group1-sha1\n\n  gss-gex-sha1-*\n\n  gss-group1-sha1-*\n\n  gss-group14-sha1-*\n\n  rsa1024-sha1\n\nNote that this plugin only checks for the options of the SSH server, and it does not check for vulnerable software versions. The remote SSH server is configured to allow weak key exchange algorithms.",
                                    "cvss": "2.6 Low CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N",
                                    "solution": "Contact the vendor or consult product documentation to disable the weak algorithms.",
                                    "risk": "SSH Weak Key Exchange Algorithms Enabled",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.nessus.org/u?b02d91cd",
                                        "https://datatracker.ietf.org/doc/html/rfc8732"
                                    ]
                                }
                            ],
                            "Denial of Service (DoS)": [
                                {
                                    "id": 788,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "The remote SSH server supports the following weak client-to-server MAC algorithm(s):\n\nhmac-md5\nhmac-md5-96\nhmac-sha1-96\n\n\nThe remote SSH server supports the following weak server-to-client MAC algorithm(s):\n\nhmac-md5\nhmac-md5-96\nhmac-sha1-96\n",
                                    "cvss": "2.6 Low AV:N/AC:H/Au:N/C:P/I:N/A:N",
                                    "solution": "Disable the reported weak MAC algorithm(s).",
                                    "risk": "Weak MAC Algorithm(s) Supported (SSH)",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        },
                        "info": {
                            "Gain Privileges": [
                                {
                                    "id": 798,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "The remote SSH host key has been generated on a Debian or Ubuntu system which contains a bug in the random number generator of its OpenSSL library.\n\nThe problem is due to a Debian packager removing nearly all sources of entropy in the remote version of OpenSSL.\n\nAn attacker can easily obtain the private part of the remote key and use this to set up decipher the remote session  or set up a man in the middle attack. The remote SSH host keys are weak.",
                                    "cvss": "10.0 High CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Consider all cryptographic material generated on the remote host to be guessable. In particuliar, all SSH, SSL and OpenVPN key material should be re-generated.",
                                    "risk": "Debian OpenSSH/OpenSSL Package Random Number Generator Weakness",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.nessus.org/u?107f9bdc",
                                        "http://www.nessus.org/u?f14f4224"
                                    ]
                                }
                            ]
                        },
                        "unknown": {
                            "Denial of Service (DoS)": [
                                {
                                    "id": 800,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "Nessus was able to identify the remote service by its banner or by looking at the error message it sends when it receives an HTTP request. The remote service could be identified.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Service Detection",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 790,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "This plugin determines the versions of the SSH protocol supported by the remote SSH daemon. A SSH server is running on the remote host.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSH Protocol Versions Supported",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 797,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "This script detects which algorithms and languages are supported by the remote service for encrypting communications. An SSH server is listening on this port.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSH Algorithms and Languages Supported",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Information Disclosure": [
                                {
                                    "id": 801,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "This plugin is a SYN 'half-open' port scanner.  It shall be reasonably quick even against a firewalled target. \n\nNote that SYN scans are less intrusive than TCP (full connect) scans against broken services, but they might cause problems for less robust firewalls and also leave unclosed connections on the remote target, if the network is loaded. It is possible to determine which TCP ports are open.",
                                    "cvss": "unknown",
                                    "solution": "Protect your target with an IP filter.",
                                    "risk": "Nessus SYN scanner",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 789,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "Security patches may have been 'backported' to the remote SSH server without changing its version number. \n\nBanner-based checks have been disabled to avoid false positives. \n\nNote that this test is informational only and does not denote any security problem. Security patches are backported.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Backported Security Patch Detection (SSH)",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://access.redhat.com/security/updates/backporting/?sc_cid=3093"
                                    ]
                                },
                                {
                                    "id": 793,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "The remote SSH server is configured to enable SHA-1 HMAC algorithms.\n\nAlthough NIST has formally deprecated use of SHA-1 for digital signatures, SHA-1 is still considered secure for HMAC as the security of HMAC does not rely on the underlying hash function being resistant to collisions.\n\nNote that this plugin only checks for the options of the remote SSH server. The remote SSH server is configured to enable SHA-1 HMAC algorithms.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSH SHA-1 HMAC Algorithms Enabled",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 799,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "It is possible to obtain information about the remote SSH server by sending an empty authentication request. An SSH server is listening on this port.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSH Server Type and Version Information",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Gain Privileges": [
                                {
                                    "id": 791,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "The SSH server on the remote host accepts password authentication. The SSH server on the remote host accepts password authentication.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSH Password Authentication Accepted",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "https://tools.ietf.org/html/rfc4252#section-8"
                                    ]
                                }
                            ],
                            "File Inclusion": [
                                {
                                    "id": 783,
                                    "host": "192.168.81.131",
                                    "service": "22/ssh",
                                    "description": "unknown",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "unknown",
                                    "type": "File Inclusion",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        }
                    },
                    "23/telnet": {
                        "medium": {
                            "Cross Site Request Forgery (CSRF)": [
                                {
                                    "id": 803,
                                    "host": "192.168.81.131",
                                    "service": "23/telnet",
                                    "description": "",
                                    "cvss": "4.8 Medium AV:A/AC:L/Au:N/C:P/I:P/A:N",
                                    "solution": "Replace Telnet with a protocol like SSH which supports encrypted connections.",
                                    "risk": "Telnet Unencrypted Cleartext Login",
                                    "type": "Cross Site Request Forgery (CSRF)",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Information Disclosure": [
                                {
                                    "id": 804,
                                    "host": "192.168.81.131",
                                    "service": "23/telnet",
                                    "description": "The remote host is running a Telnet server over an unencrypted channel.\n\nUsing Telnet over an unencrypted channel is not recommended as logins, passwords, and commands are transferred in cleartext. This allows a remote, man-in-the-middle attacker to eavesdrop on a Telnet session to obtain credentials or other sensitive information and to modify traffic exchanged between a client and server.\n\nSSH is preferred over Telnet since it protects credentials from eavesdropping and can tunnel additional data streams such as an X11 session. The remote Telnet server transmits traffic in cleartext.",
                                    "cvss": "5.8 Medium CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N",
                                    "solution": "Disable the Telnet service and use SSH instead.",
                                    "risk": "Unencrypted Telnet Server",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        },
                        "unknown": {
                            "Denial of Service (DoS)": [
                                {
                                    "id": 806,
                                    "host": "192.168.81.131",
                                    "service": "23/telnet",
                                    "description": "Nessus was able to identify the remote service by its banner or by looking at the error message it sends when it receives an HTTP request. The remote service could be identified.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Service Detection",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Information Disclosure": [
                                {
                                    "id": 807,
                                    "host": "192.168.81.131",
                                    "service": "23/telnet",
                                    "description": "This plugin is a SYN 'half-open' port scanner.  It shall be reasonably quick even against a firewalled target. \n\nNote that SYN scans are less intrusive than TCP (full connect) scans against broken services, but they might cause problems for less robust firewalls and also leave unclosed connections on the remote target, if the network is loaded. It is possible to determine which TCP ports are open.",
                                    "cvss": "unknown",
                                    "solution": "Protect your target with an IP filter.",
                                    "risk": "Nessus SYN scanner",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Gain Privileges": [
                                {
                                    "id": 805,
                                    "host": "192.168.81.131",
                                    "service": "23/telnet",
                                    "description": "The remote host is running a Telnet server, a remote terminal server. A Telnet server is listening on the remote port.",
                                    "cvss": "unknown",
                                    "solution": "Disable this service if you do not use it.",
                                    "risk": "Telnet Server Detection",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "File Inclusion": [
                                {
                                    "id": 802,
                                    "host": "192.168.81.131",
                                    "service": "23/telnet",
                                    "description": "unknown",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "unknown",
                                    "type": "File Inclusion",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        }
                    },
                    "25/smtp": {
                        "critical": {
                            "Information Disclosure": [
                                {
                                    "id": 824,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote service accepts connections encrypted using SSL 2.0 and/or SSL 3.0. These versions of SSL are affected by several cryptographic flaws, including:\n\n  - An insecure padding scheme with CBC ciphers.\n\n  - Insecure session renegotiation and resumption schemes.\n\nAn attacker can exploit these flaws to conduct man-in-the-middle attacks or to decrypt communications between the affected service and clients.\n\nAlthough SSL/TLS has a secure means for choosing the highest supported version of the protocol (so that these versions will be used only if the client or server support nothing better), many web browsers implement this in an unsafe way that allows an attacker to downgrade a connection (such as in POODLE). Therefore, it is recommended that these protocols be disabled entirely.\n\nNIST has determined that SSL 3.0 is no longer acceptable for secure communications. As of the date of enforcement found in PCI DSS v3.1, any version of SSL will not meet the PCI SSC's definition of 'strong cryptography'. The remote service encrypts traffic using a protocol with known weaknesses.",
                                    "cvss": "10.0 High CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Consult the application's documentation to disable SSL 2.0 and 3.0.\nUse TLS 1.2 (with approved cipher suites) or higher instead.",
                                    "risk": "SSL Version 2 and 3 Protocol Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.schneier.com/academic/paperfiles/paper-ssl.pdf",
                                        "http://www.nessus.org/u?b06c7e95",
                                        "http://www.nessus.org/u?247c4540",
                                        "https://www.openssl.org/~bodo/ssl-poodle.pdf",
                                        "http://www.nessus.org/u?5d15ba70",
                                        "https://www.imperialviolet.org/2014/10/14/poodle.html",
                                        "https://tools.ietf.org/html/rfc7507",
                                        "https://tools.ietf.org/html/rfc7568"
                                    ]
                                }
                            ],
                            "Gain Privileges": [
                                {
                                    "id": 843,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote x509 certificate on the remote SSL server has been generated on a Debian or Ubuntu system which contains a bug in the random number generator of its OpenSSL library. \n\nThe problem is due to a Debian packager removing nearly all sources of entropy in the remote version of OpenSSL. \n\nAn attacker can easily obtain the private part of the remote key and use this to decipher the remote session or set up a man in the middle attack. The remote SSL certificate uses a weak key.",
                                    "cvss": "10.0 High CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Consider all cryptographic material generated on the remote host to be guessable.  In particuliar, all SSH, SSL and OpenVPN key material should be re-generated.",
                                    "risk": "Debian OpenSSH/OpenSSL Package Random Number Generator Weakness (SSL check)",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.nessus.org/u?107f9bdc",
                                        "http://www.nessus.org/u?f14f4224"
                                    ]
                                }
                            ]
                        },
                        "medium": {
                            "Information Disclosure": [
                                {
                                    "id": 809,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other products, uses nondeterministic CBC padding, which makes it easier for man-in-the-middle attackers to obtain cleartext data via a padding-oracle attack, aka the \"POODLE\" issue.\n\nThe STARTTLS implementation in Postfix 2.4.x before 2.4.16, 2.5.x before 2.5.12, 2.6.x before 2.6.9, and 2.7.x before 2.7.3 does not properly restrict I/O buffering, which allows man-in-the-middle attackers to insert commands into encrypted SMTP sessions by sending a cleartext command that is processed after TLS is in place, related to a \"plaintext command injection\" attack.\n\n",
                                    "cvss": "6.8 Medium AV:N/AC:M/Au:N/C:P/I:P/A:P",
                                    "solution": "Updates are available. Please see the references for more\n  information.",
                                    "risk": "Multiple Vendors STARTTLS Implementation Plaintext Arbitrary Command Injection Vulnerability",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2011-0411",
                                        "CVE-2014-3566"
                                    ],
                                    "refs": [],
                                    "exploits": [
                                        null
                                    ],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 810,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and other products, requires a server to send a ServerVerify message before establishing that a client possesses certain plaintext RSA data, which makes it easier for remote attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding oracle, aka a \"DROWN\" attack.\n\nIn addition to TLSv1.0+ the service is also providing the deprecated SSLv2 and SSLv3 protocols and supports one or more ciphers. Those supported ciphers can be found in the 'SSL/TLS: Report Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.802067) VT.\n",
                                    "cvss": "5.9 Medium CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "solution": "It is recommended to disable the deprecated SSLv2 and/or SSLv3\n  protocols in favor of the TLSv1.2+ protocols. Please see the references for more information.",
                                    "risk": "SSL/TLS: Deprecated SSLv2 and SSLv3 Protocol Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2016-0800"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 811,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote SSL/TLS server is using the following certificate(s) with a RSA key with less than 2048 bits (public-key-size:public-key-algorithm:serial:issuer):\n\n1024:RSA:00FAF93A4C7FB6B9CC:1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX (Server certificate)\n",
                                    "cvss": "5.3 Medium CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "solution": "Replace the certificate with a stronger key and reissue the\n  certificates it signed.",
                                    "risk": "SSL/TLS: Server Certificate / Certificate in Chain with RSA keys less than 2048 bits",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.cabforum.org/wp-content/uploads/Baseline_Requirements_V1.pdf"
                                    ]
                                },
                                {
                                    "id": 812,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The certificate of the remote service expired on 2010-04-16 14:07:45.\n\nCertificate details:\nfingerprint (SHA-1)             | ED093088706603BFD5DC237399B498DA2D4D31C6\nfingerprint (SHA-256)           | E7A7FA0D63E457C7C4A59B38B70849C6A70BDA6F830C7AF1E32DEE436DE813CC\nissued by                       | 1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX\npublic key algorithm            | RSA\npublic key size (bits)          | 1024\nserial                          | 00FAF93A4C7FB6B9CC\nsignature algorithm             | sha1WithRSAEncryption\nsubject                         | 1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX\nsubject alternative names (SAN) | None\nvalid from                      | 2010-03-17 14:07:45 UTC\nvalid until                     | 2010-04-16 14:07:45 UTC\n",
                                    "cvss": "5.0 Medium AV:N/AC:L/Au:N/C:N/I:P/A:N",
                                    "solution": "Replace the SSL/TLS certificate by a new one.",
                                    "risk": "SSL/TLS: Certificate Expired",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 814,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The SSL protocol, as used in certain configurations in Microsoft Windows and Microsoft Internet Explorer, Mozilla Firefox, Google Chrome, Opera, and other products, encrypts data by using CBC mode with chained initialization vectors, which allows man-in-the-middle attackers to obtain plaintext HTTP headers via a blockwise chosen-boundary attack (BCBA) on an HTTPS session, in conjunction with JavaScript code that uses (1) the HTML5 WebSocket API, (2) the Java URLConnection API, or (3) the Silverlight WebClient API, aka a \"BEAST\" attack.\n\nThe service is only providing the deprecated TLSv1.0 protocol and supports one or more ciphers. Those supported ciphers can be found in the 'SSL/TLS: Report Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.802067) VT.\n",
                                    "cvss": "4.3 Medium AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "solution": "It is recommended to disable the deprecated TLSv1.0 and/or\n  TLSv1.1 protocols in favor of the TLSv1.2+ protocols. Please see the references for more\n  information.",
                                    "risk": "SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2011-3389"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 815,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "A vulnerability in the OpenSSL ssl3_get_key_exchange function could allow a remote attacker to downgrade the security of certain TLS connections. An OpenSSL client accepts the use of an RSA temporary key in a non-export RSA key exchange ciphersuite. This could allow a remote attacker using man-in-the-middle techniques to facilitate brute-force decryption of TLS/SSL traffic between vulnerable clients and servers.\n\nThis vulnerability is also known as the FREAK attack.\n\nThe ssl3_get_key_exchange function in s3_clnt.c in OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k allows remote SSL servers to conduct RSA-to-EXPORT_RSA downgrade attacks and facilitate brute-force decryption by offering a weak ephemeral RSA key in a noncompliant role, related to the \"FREAK\" issue.  NOTE: the scope of this CVE is only client code based on OpenSSL, not EXPORT_RSA issues associated with servers or other TLS implementations.\n\n'RSA_EXPORT' cipher suites accepted by this service via the SSLv3 protocol:\n\nTLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA\nTLS_RSA_EXPORT_WITH_DES40_CBC_SHA\nTLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5\nTLS_RSA_EXPORT_WITH_RC4_40_MD5\n\n'RSA_EXPORT' cipher suites accepted by this service via the TLSv1.0 protocol:\n\nTLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA\nTLS_RSA_EXPORT_WITH_DES40_CBC_SHA\nTLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5\nTLS_RSA_EXPORT_WITH_RC4_40_MD5\n\n\n",
                                    "cvss": "4.3 Medium AV:N/AC:M/Au:N/C:N/I:P/A:N",
                                    "solution": "Refer to OpenSSL Security Advisory [08 Jan 2015] for patch, upgrade or suggested workaround information. See References.\n\nFor IBM products:\nRefer to the appropriate IBM Security Bulletin for patch, upgrade or suggested workaround information. See References.\n\nFor other distributions:\nApply the appropriate update for your system.. Maggiori info (https://exchange.xforce.ibmcloud.com/vulnerabilities/99707)\n\n- Remove support for 'RSA_EXPORT' cipher\n  suites from the service.\n\n  - If running OpenSSL update to version 0.9.8zd or 1.0.0p\n  or 1.0.1k or later.",
                                    "risk": "SSL/TLS: RSA Temporary Key Handling 'RSA_EXPORT' Downgrade Issue (FREAK)",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2015-0204"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 817,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The following certificates are part of the certificate chain but using insecure signature algorithms:\n\nSubject:              1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX\nSignature Algorithm:  sha1WithRSAEncryption\n\n\n",
                                    "cvss": "4.0 Medium AV:N/AC:H/Au:N/C:P/I:P/A:N",
                                    "solution": "Servers that use SSL/TLS certificates signed with a weak SHA-1, MD5, MD4 or MD2 hashing algorithm will need to obtain new\n  SHA-2 signed SSL/TLS certificates to avoid web browser SSL/TLS certificate warnings.",
                                    "risk": "SSL/TLS: Certificate Signed Using A Weak Signature Algorithm",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://blog.mozilla.org/security/2014/09/23/phasing-out-certificates-with-sha-1-based-signature-algorithms/"
                                    ]
                                },
                                {
                                    "id": 820,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote SMTP service contains a software flaw in its STARTTLS implementation that could allow a remote, unauthenticated attacker to inject commands during the plaintext protocol phase that will be executed during the ciphertext protocol phase. \n\nSuccessful exploitation could allow an attacker to steal a victim's email or associated SASL (Simple Authentication and Security Layer) credentials. The remote mail service allows plaintext command injection while negotiating an encrypted communications channel.",
                                    "cvss": "4.0 Medium CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N",
                                    "solution": "Contact the vendor to see if an update is available.",
                                    "risk": "SMTP Service STARTTLS Plaintext Command Injection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://tools.ietf.org/html/rfc2487",
                                        "https://www.securityfocus.com/archive/1/516901/30/0/threaded"
                                    ]
                                },
                                {
                                    "id": 826,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote host supports SSLv2 and therefore may be affected by a vulnerability that allows a cross-protocol Bleichenbacher padding oracle attack known as DROWN (Decrypting RSA with Obsolete and Weakened eNcryption). This vulnerability exists due to a flaw in the Secure Sockets Layer Version 2 (SSLv2) implementation, and it allows captured TLS traffic to be decrypted. A man-in-the-middle attacker can exploit this to decrypt the TLS connection by utilizing previously captured traffic and weak cryptography along with a series of specially crafted connections to an SSLv2 server that uses the same private key. The remote host may be affected by a vulnerability that allows a remote attacker to potentially decrypt captured TLS traffic.",
                                    "cvss": "4.3 Medium CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "solution": "Disable SSLv2 and export grade cryptography cipher suites. Ensure that private keys are not used anywhere with server software that supports SSLv2 connections.",
                                    "risk": "SSL DROWN Attack Vulnerability (Decrypting RSA with Obsolete and Weakened eNcryption)",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://drownattack.com/",
                                        "https://drownattack.com/drown-attack-paper.pdf"
                                    ]
                                },
                                {
                                    "id": 829,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote host supports the use of RC4 in one or more cipher suites.\nThe RC4 cipher is flawed in its generation of a pseudo-random stream of bytes so that a wide variety of small biases are introduced into the stream, decreasing its randomness.\n\nIf plaintext is repeatedly encrypted (e.g., HTTP cookies), and an attacker is able to obtain many (i.e., tens of millions) ciphertexts, the attacker may be able to derive the plaintext. The remote service supports the use of the RC4 cipher.",
                                    "cvss": "4.3 Medium CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "solution": "Reconfigure the affected application, if possible, to avoid use of RC4 ciphers. Consider using TLS 1.2 with AES-GCM suites subject to browser and web server support.",
                                    "risk": "SSL RC4 Cipher Suites Supported (Bar Mitzvah)",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.rc4nomore.com/",
                                        "http://www.nessus.org/u?ac7327a0",
                                        "http://cr.yp.to/talks/2013.03.12/slides.pdf",
                                        "http://www.isg.rhul.ac.uk/tls/",
                                        "https://www.imperva.com/docs/HII_Attacking_SSL_when_using_RC4.pdf"
                                    ]
                                },
                                {
                                    "id": 831,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote host is affected by a man-in-the-middle (MitM) information disclosure vulnerability known as POODLE. The vulnerability is due to the way SSL 3.0 handles padding bytes when decrypting messages encrypted using block ciphers in cipher block chaining (CBC) mode.\nMitM attackers can decrypt a selected byte of a cipher text in as few as 256 tries if they are able to force a victim application to repeatedly send the same data over newly created SSL 3.0 connections.\n\nAs long as a client and service both support SSLv3, a connection can be 'rolled back' to SSLv3, even if TLSv1 or newer is supported by the client and service.\n\nThe TLS Fallback SCSV mechanism prevents 'version rollback' attacks without impacting legacy clients; however, it can only protect connections when the client and service support the mechanism. Sites that cannot disable SSLv3 immediately should enable this mechanism.\n\nThis is a vulnerability in the SSLv3 specification, not in any particular SSL implementation. Disabling SSLv3 is the only way to completely mitigate the vulnerability. It is possible to obtain sensitive information from the remote host with SSL/TLS-enabled services.",
                                    "cvss": "4.3 Medium CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "solution": "Disable SSLv3.\n\nServices that must support SSLv3 should enable the TLS Fallback SCSV mechanism until SSLv3 can be disabled.",
                                    "risk": "SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.imperialviolet.org/2014/10/14/poodle.html",
                                        "https://www.openssl.org/~bodo/ssl-poodle.pdf",
                                        "https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00"
                                    ]
                                },
                                {
                                    "id": 836,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote service accepts connections encrypted using TLS 1.0. TLS 1.0 has a number of cryptographic design flaws. Modern implementations of TLS 1.0 mitigate these problems, but newer versions of TLS like 1.2 and 1.3 are designed against these flaws and should be used whenever possible.\n\nAs of March 31, 2020, Endpoints that aren’t enabled for TLS 1.2 and higher will no longer function properly with major web browsers and major vendors.\n\nPCI DSS v3.2 requires that TLS 1.0 be disabled entirely by June 30, 2018, except for POS POI terminals (and the SSL/TLS termination points to which they connect) that can be verified as not being susceptible to any known exploits. The remote service encrypts traffic using an older version of TLS.",
                                    "cvss": "6.1 Medium CVSS2#AV:N/AC:H/Au:N/C:C/I:P/A:N",
                                    "solution": "Enable support for TLS 1.2 and 1.3, and disable support for TLS 1.0.",
                                    "risk": "TLS Version 1.0 Protocol Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://tools.ietf.org/html/draft-ietf-tls-oldversions-deprecate-00"
                                    ]
                                },
                                {
                                    "id": 841,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The X.509 certificate chain for this service is not signed by a recognized certificate authority.  If the remote host is a public host in production, this nullifies the use of SSL as anyone could establish a man-in-the-middle attack against the remote host. \n\nNote that this plugin does not check for certificate chains that end in a certificate that is not self-signed, but is signed by an unrecognized certificate authority. The SSL certificate chain for this service ends in an unrecognized self-signed certificate.",
                                    "cvss": "6.4 Medium CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N",
                                    "solution": "Purchase or generate a proper SSL certificate for this service.",
                                    "risk": "SSL Self-Signed Certificate",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 842,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "This plugin checks expiry dates of certificates associated with SSL- enabled services on the target and reports whether any have already expired. The remote server's SSL certificate has already expired.",
                                    "cvss": "5.0 Medium CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N",
                                    "solution": "Purchase or generate a new SSL certificate to replace the existing one.",
                                    "risk": "SSL Certificate Expiry",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 845,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote service encrypts traffic using TLS / SSL but allows a client to insecurely renegotiate the connection after the initial handshake.\nAn unauthenticated, remote attacker may be able to leverage this issue to inject an arbitrary amount of plaintext into the beginning of the application protocol stream, which could facilitate man-in-the-middle attacks if the service assumes that the sessions before and after renegotiation are from the same 'client' and merges them at the application layer. The remote service allows insecure renegotiation of TLS / SSL connections.",
                                    "cvss": "5.8 Medium CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P",
                                    "solution": "Contact the vendor for specific patch information.",
                                    "risk": "SSL / TLS Renegotiation Handshakes MiTM Plaintext Data Injection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.ietf.org/mail-archive/web/tls/current/msg03948.html",
                                        "http://www.g-sec.lu/practicaltls.pdf",
                                        "https://tools.ietf.org/html/rfc5746"
                                    ]
                                }
                            ],
                            "Execute arbitrary code on vulnerable system": [
                                {
                                    "id": 813,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "'VRFY root' produces the following answer: 252 2.0.0 root\n\n\n",
                                    "cvss": "5.0 Medium AV:N/AC:L/Au:N/C:N/I:N/A:P",
                                    "solution": "Disable VRFY and/or EXPN on your Mailserver.\n\n  For postfix add 'disable_vrfy_command=yes' in 'main.cf'.\n\n  For Sendmail add the option 'O PrivacyOptions=goaway'.\n\n  It is suggested that, if you really want to publish this type of information, you use a mechanism\n  that legitimate users actually know about, such as Finger or HTTP.",
                                    "risk": "Check if Mailserver answer to VRFY and EXPN requests",
                                    "type": "Execute arbitrary code on vulnerable system",
                                    "id_cve": [],
                                    "refs": [
                                        "http://cr.yp.to/smtp/vrfy.html"
                                    ]
                                }
                            ],
                            "Memory Corruption": [
                                {
                                    "id": 816,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "Server Temporary Key Size: 1024 bits\n\n",
                                    "cvss": "4.0 Medium AV:N/AC:H/Au:N/C:P/I:P/A:N",
                                    "solution": "Deploy (Ephemeral) Elliptic-Curve Diffie-Hellman (ECDHE) or use\n  a 2048-bit or stronger Diffie-Hellman group (see the references).\n\n  For Apache Web Servers:\n  Beginning with version 2.4.7, mod_ssl will use DH parameters which include primes with lengths of more than 1024 bits.",
                                    "risk": "SSL/TLS: Diffie-Hellman Key Exchange Insufficient DH Group Strength Vulnerability",
                                    "type": "Memory Corruption",
                                    "id_cve": [],
                                    "refs": [
                                        "https://weakdh.org/"
                                    ]
                                }
                            ],
                            "Denial of Service (DoS)": [
                                {
                                    "id": 821,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The version of OpenSSL on the remote host has been shown to allow resuming session with a weaker cipher than was used when the session was initiated.  This means that an attacker that sees (i.e., by sniffing) the start of an SSL connection can manipulate the OpenSSL session cache to cause subsequent resumptions of that session to use a weaker cipher chosen by the attacker.\n\nNote that other SSL implementations may also be affected by this vulnerability. The remote host allows resuming SSL sessions with a weaker cipher than the one originally negotiated.",
                                    "cvss": "4.3 Medium CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N",
                                    "solution": "Upgrade to OpenSSL 0.9.8q / 1.0.0.c or later, or contact your vendor for a patch.",
                                    "risk": "OpenSSL SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG Session Resume Ciphersuite Downgrade Issue",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.openssl.org/news/secadv/20101202.txt"
                                    ]
                                },
                                {
                                    "id": 834,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote host supports the use of SSL ciphers that offer weak encryption.\n\nNote: This is considerably easier to exploit if the attacker is on the same physical network. The remote service supports the use of weak SSL ciphers.",
                                    "cvss": "4.3 Medium CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "solution": "Reconfigure the affected application, if possible to avoid the use of weak ciphers.",
                                    "risk": "SSL Weak Cipher Suites Supported",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.nessus.org/u?6527892d"
                                    ]
                                },
                                {
                                    "id": 838,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The 'commonName' (CN) attribute of the SSL certificate presented for this service is for a different machine. The SSL certificate for this service is for a different host.",
                                    "cvss": "5.0 Medium CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N",
                                    "solution": "Purchase or generate a proper SSL certificate for this service.",
                                    "risk": "SSL Certificate with Wrong Hostname",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Gain Privileges": [
                                {
                                    "id": 832,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote host supports EXPORT_RSA cipher suites with keys less than or equal to 512 bits. An attacker can factor a 512-bit RSA modulus in a short amount of time.\n\nA man-in-the middle attacker may be able to downgrade the session to use EXPORT_RSA cipher suites (e.g. CVE-2015-0204). Thus, it is recommended to remove support for weak cipher suites. The remote host supports a set of weak ciphers.",
                                    "cvss": "4.3 Medium CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N",
                                    "solution": "Reconfigure the service to remove support for EXPORT_RSA cipher suites.",
                                    "risk": "SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.smacktls.com/#freak",
                                        "https://www.openssl.org/news/secadv/20150108.txt",
                                        "http://www.nessus.org/u?b78da2c4"
                                    ]
                                },
                                {
                                    "id": 835,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote host supports the use of SSL ciphers that offer medium strength encryption. Nessus regards medium strength as any encryption that uses key lengths at least 64 bits and less than 112 bits, or else that uses the 3DES encryption suite.\n\nNote that it is considerably easier to circumvent medium strength encryption if the attacker is on the same physical network. The remote service supports the use of medium strength SSL ciphers.",
                                    "cvss": "5.0 Medium CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N",
                                    "solution": "Reconfigure the affected application if possible to avoid use of medium strength ciphers.",
                                    "risk": "SSL Medium Strength Cipher Suites Supported (SWEET32)",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.openssl.org/blog/blog/2016/08/24/sweet32/",
                                        "https://sweet32.info"
                                    ]
                                },
                                {
                                    "id": 840,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The server's X.509 certificate cannot be trusted. This situation can occur in three different ways, in which the chain of trust can be broken, as stated below :\n\n  - First, the top of the certificate chain sent by the     server might not be descended from a known public     certificate authority. This can occur either when the     top of the chain is an unrecognized, self-signed     certificate, or when intermediate certificates are     missing that would connect the top of the certificate     chain to a known public certificate authority.\n\n  - Second, the certificate chain may contain a certificate     that is not valid at the time of the scan. This can     occur either when the scan occurs before one of the     certificate's 'notBefore' dates, or after one of the     certificate's 'notAfter' dates.\n\n  - Third, the certificate chain may contain a signature     that either didn't match the certificate's information     or could not be verified. Bad signatures can be fixed by     getting the certificate with the bad signature to be     re-signed by its issuer. Signatures that could not be     verified are the result of the certificate's issuer     using a signing algorithm that Nessus either does not     support or does not recognize.\n\nIf the remote host is a public host in production, any break in the chain makes it more difficult for users to verify the authenticity and identity of the web server. This could make it easier to carry out man-in-the-middle attacks against the remote host. The SSL certificate for this service cannot be trusted.",
                                    "cvss": "6.4 Medium CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N",
                                    "solution": "Purchase or generate a proper SSL certificate for this service.",
                                    "risk": "SSL Certificate Cannot Be Trusted",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.itu.int/rec/T-REC-X.509/en",
                                        "https://en.wikipedia.org/wiki/X.509"
                                    ]
                                }
                            ]
                        },
                        "low": {
                            "Information Disclosure": [
                                {
                                    "id": 810,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and other products, requires a server to send a ServerVerify message before establishing that a client possesses certain plaintext RSA data, which makes it easier for remote attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding oracle, aka a \"DROWN\" attack.\n\nIn addition to TLSv1.0+ the service is also providing the deprecated SSLv2 and SSLv3 protocols and supports one or more ciphers. Those supported ciphers can be found in the 'SSL/TLS: Report Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.802067) VT.\n",
                                    "cvss": "5.9 Medium CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "solution": "It is recommended to disable the deprecated SSLv2 and/or SSLv3\n  protocols in favor of the TLSv1.2+ protocols. Please see the references for more information.",
                                    "risk": "SSL/TLS: Deprecated SSLv2 and SSLv3 Protocol Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2016-0800"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 811,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote SSL/TLS server is using the following certificate(s) with a RSA key with less than 2048 bits (public-key-size:public-key-algorithm:serial:issuer):\n\n1024:RSA:00FAF93A4C7FB6B9CC:1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX (Server certificate)\n",
                                    "cvss": "5.3 Medium CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "solution": "Replace the certificate with a stronger key and reissue the\n  certificates it signed.",
                                    "risk": "SSL/TLS: Server Certificate / Certificate in Chain with RSA keys less than 2048 bits",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.cabforum.org/wp-content/uploads/Baseline_Requirements_V1.pdf"
                                    ]
                                },
                                {
                                    "id": 818,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The TLS protocol 1.2 and earlier, when a DHE_EXPORT ciphersuite is enabled on a server but not on a client, does not properly convey a DHE_EXPORT choice, which allows man-in-the-middle attackers to conduct cipher-downgrade attacks by rewriting a ClientHello with DHE replaced by DHE_EXPORT and then rewriting a ServerHello with DHE_EXPORT replaced by DHE, aka the \"Logjam\" issue.\n\n'DHE_EXPORT' cipher suites accepted by this service via the SSLv3 protocol:\n\nTLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA\nTLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA\nTLS_DH_anon_EXPORT_WITH_RC4_40_MD5\n\n'DHE_EXPORT' cipher suites accepted by this service via the TLSv1.0 protocol:\n\nTLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA\nTLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA\nTLS_DH_anon_EXPORT_WITH_RC4_40_MD5\n\n\n",
                                    "cvss": "3.7 Low CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                                    "solution": "- Remove support for 'DHE_EXPORT' cipher\n  suites from the service\n\n  - If running OpenSSL updateto version 1.0.2b or 1.0.1n or later.",
                                    "risk": "SSL/TLS: 'DHE_EXPORT' Man in the Middle Security Bypass Vulnerability (LogJam)",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2015-4000"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 822,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote host supports the use of anonymous SSL ciphers. While this enables an administrator to set up a service that encrypts traffic without having to generate and configure SSL certificates, it offers no way to verify the remote host's identity and renders the service vulnerable to a man-in-the-middle attack.\n\nNote: This is considerably easier to exploit if the attacker is on the same physical network. The remote service supports the use of anonymous SSL ciphers.",
                                    "cvss": "2.6 Low CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N",
                                    "solution": "Reconfigure the affected application if possible to avoid use of weak ciphers.",
                                    "risk": "SSL Anonymous Cipher Suites Supported",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.nessus.org/u?3a040ada"
                                    ]
                                },
                                {
                                    "id": 825,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote host supports EXPORT_DHE cipher suites with keys less than or equal to 512 bits. Through cryptanalysis, a third party can find the shared secret in a short amount of time.\n\nA man-in-the middle attacker may be able to downgrade the session to use EXPORT_DHE cipher suites. Thus, it is recommended to remove support for weak cipher suites. The remote host supports a set of weak ciphers.",
                                    "cvss": "2.6 Low CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N",
                                    "solution": "Reconfigure the service to remove support for EXPORT_DHE cipher suites.",
                                    "risk": "SSL/TLS EXPORT_DHE <= 512-bit Export Cipher Suites Supported (Logjam)",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://weakdh.org/"
                                    ]
                                }
                            ]
                        },
                        "info": {
                            "Information Disclosure": [
                                {
                                    "id": 824,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote service accepts connections encrypted using SSL 2.0 and/or SSL 3.0. These versions of SSL are affected by several cryptographic flaws, including:\n\n  - An insecure padding scheme with CBC ciphers.\n\n  - Insecure session renegotiation and resumption schemes.\n\nAn attacker can exploit these flaws to conduct man-in-the-middle attacks or to decrypt communications between the affected service and clients.\n\nAlthough SSL/TLS has a secure means for choosing the highest supported version of the protocol (so that these versions will be used only if the client or server support nothing better), many web browsers implement this in an unsafe way that allows an attacker to downgrade a connection (such as in POODLE). Therefore, it is recommended that these protocols be disabled entirely.\n\nNIST has determined that SSL 3.0 is no longer acceptable for secure communications. As of the date of enforcement found in PCI DSS v3.1, any version of SSL will not meet the PCI SSC's definition of 'strong cryptography'. The remote service encrypts traffic using a protocol with known weaknesses.",
                                    "cvss": "10.0 High CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Consult the application's documentation to disable SSL 2.0 and 3.0.\nUse TLS 1.2 (with approved cipher suites) or higher instead.",
                                    "risk": "SSL Version 2 and 3 Protocol Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.schneier.com/academic/paperfiles/paper-ssl.pdf",
                                        "http://www.nessus.org/u?b06c7e95",
                                        "http://www.nessus.org/u?247c4540",
                                        "https://www.openssl.org/~bodo/ssl-poodle.pdf",
                                        "http://www.nessus.org/u?5d15ba70",
                                        "https://www.imperialviolet.org/2014/10/14/poodle.html",
                                        "https://tools.ietf.org/html/rfc7507",
                                        "https://tools.ietf.org/html/rfc7568"
                                    ]
                                }
                            ],
                            "Gain Privileges": [
                                {
                                    "id": 843,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote x509 certificate on the remote SSL server has been generated on a Debian or Ubuntu system which contains a bug in the random number generator of its OpenSSL library. \n\nThe problem is due to a Debian packager removing nearly all sources of entropy in the remote version of OpenSSL. \n\nAn attacker can easily obtain the private part of the remote key and use this to decipher the remote session or set up a man in the middle attack. The remote SSL certificate uses a weak key.",
                                    "cvss": "10.0 High CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Consider all cryptographic material generated on the remote host to be guessable.  In particuliar, all SSH, SSL and OpenVPN key material should be re-generated.",
                                    "risk": "Debian OpenSSH/OpenSSL Package Random Number Generator Weakness (SSL check)",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.nessus.org/u?107f9bdc",
                                        "http://www.nessus.org/u?f14f4224"
                                    ]
                                }
                            ]
                        },
                        "unknown": {
                            "Denial of Service (DoS)": [
                                {
                                    "id": 849,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "Nessus was able to identify the remote service by its banner or by looking at the error message it sends when it receives an HTTP request. The remote service could be identified.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Service Detection",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 830,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote host has open SSL/TLS ports which advertise discouraged cipher suites. It is recommended to only enable support for the following cipher suites:\n\nTLSv1.3:\n  - 0x13,0x01 TLS_AES_128_GCM_SHA256\n  - 0x13,0x02 TLS_AES_256_GCM_SHA384\n  - 0x13,0x03 TLS_CHACHA20_POLY1305_SHA256\n\nTLSv1.2:\n  - 0xC0,0x2B ECDHE-ECDSA-AES128-GCM-SHA256\n  - 0xC0,0x2F ECDHE-RSA-AES128-GCM-SHA256\n  - 0xC0,0x2C ECDHE-ECDSA-AES256-GCM-SHA384\n  - 0xC0,0x30 ECDHE-RSA-AES256-GCM-SHA384\n  - 0xCC,0xA9 ECDHE-ECDSA-CHACHA20-POLY1305\n  - 0xCC,0xA8 ECDHE-RSA-CHACHA20-POLY1305\n  - 0x00,0x9E DHE-RSA-AES128-GCM-SHA256\n  - 0x00,0x9F DHE-RSA-AES256-GCM-SHA384\n\nThis is the recommended configuration for the vast majority of services, as it is highly secure and compatible with nearly every client released in the last five (or more) years. The remote host advertises discouraged SSL/TLS ciphers.",
                                    "cvss": "unknown",
                                    "solution": "Only enable support for recommened cipher suites.",
                                    "risk": "SSL/TLS Recommended Cipher Suites",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "https://wiki.mozilla.org/Security/Server_Side_TLS",
                                        "https://ssl-config.mozilla.org/"
                                    ]
                                },
                                {
                                    "id": 837,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "This plugin detects which SSL ciphers are supported by the remote service for encrypting communications. The remote service encrypts communications using SSL.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSL Cipher Suites Supported",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.openssl.org/docs/man1.0.2/man1/ciphers.html",
                                        "http://www.nessus.org/u?e17ffced"
                                    ]
                                },
                                {
                                    "id": 839,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The service running on the remote host presents an SSL certificate for which the 'commonName' (CN) attribute does not match the hostname on which the service listens. The 'commonName' (CN) attribute in the SSL certificate does not match the hostname.",
                                    "cvss": "unknown",
                                    "solution": "If the machine has several names, make sure that users connect to the service through the DNS hostname that matches the common name in the certificate.",
                                    "risk": "SSL Certificate 'commonName' Mismatch",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 846,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "This plugin detects which SSL and TLS versions are supported by the remote service for encrypting communications. The remote service encrypts communications.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSL / TLS Versions Supported",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Information Disclosure": [
                                {
                                    "id": 850,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "This plugin is a SYN 'half-open' port scanner.  It shall be reasonably quick even against a firewalled target. \n\nNote that SYN scans are less intrusive than TCP (full connect) scans against broken services, but they might cause problems for less robust firewalls and also leave unclosed connections on the remote target, if the network is loaded. It is possible to determine which TCP ports are open.",
                                    "cvss": "unknown",
                                    "solution": "Protect your target with an IP filter.",
                                    "risk": "Nessus SYN scanner",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 823,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote host supports the use of SSL ciphers that operate in Cipher Block Chaining (CBC) mode.  These cipher suites offer additional security over Electronic Codebook (ECB) mode, but have the potential to leak information if used improperly. The remote service supports the use of SSL Cipher Block Chaining ciphers, which combine previous blocks with subsequent ones.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSL Cipher Block Chaining Cipher Suites Supported",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.openssl.org/docs/manmaster/man1/ciphers.html",
                                        "http://www.nessus.org/u?cc4a822a",
                                        "https://www.openssl.org/~bodo/tls-cbc.txt"
                                    ]
                                },
                                {
                                    "id": 833,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote host supports the use of SSL ciphers that offer Perfect Forward Secrecy (PFS) encryption.  These cipher suites ensure that recorded SSL traffic cannot be broken at a future date if the server's private key is compromised. The remote service supports the use of SSL Perfect Forward Secrecy ciphers, which maintain confidentiality even if the key is stolen.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSL Perfect Forward Secrecy Cipher Suites Supported",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.openssl.org/docs/manmaster/man1/ciphers.html",
                                        "https://en.wikipedia.org/wiki/Diffie-Hellman_key_exchange",
                                        "https://en.wikipedia.org/wiki/Perfect_forward_secrecy"
                                    ]
                                },
                                {
                                    "id": 844,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "This plugin connects to every SSL-related port and attempts to extract and dump the X.509 certificate. This plugin displays the SSL certificate.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSL Certificate Information",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 847,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote SMTP service supports the use of the 'STARTTLS' command to switch from a cleartext to an encrypted communications channel. The remote mail service supports encrypting traffic.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SMTP Service STARTTLS Command Support",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://en.wikipedia.org/wiki/STARTTLS",
                                        "https://tools.ietf.org/html/rfc2487"
                                    ]
                                },
                                {
                                    "id": 848,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The remote host is running a mail (SMTP) server on this port. \n\nSince SMTP servers are the targets of spammers, it is recommended you disable it if you do not use it. An SMTP server is listening on the remote port.",
                                    "cvss": "unknown",
                                    "solution": "Disable this service if you do not use it, or filter incoming traffic to this port.",
                                    "risk": "SMTP Server Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Gain Privileges": [
                                {
                                    "id": 808,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "Transport Layer Security (TLS) services that use Diffie-Hellman groups\nof insufficient strength, especially those using one of a few commonly\nshared groups, may be susceptible to passive eavesdropping attacks.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "sslv2-drown",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "https://weakdh.org"
                                    ]
                                }
                            ],
                            "Memory Corruption": [
                                {
                                    "id": 827,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "The SSL implementation on the remote host has been shown to allow a cipher other than the one originally negotiated when resuming a session. An attacker that sees (e.g. by sniffing) the start of an SSL connection may be able to manipulate session cache to cause subsequent resumptions of that session to use a cipher chosen by the attacker. The remote host allows resuming SSL sessions with a different cipher than the one originally negotiated.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSL Resume With Different Cipher Issue",
                                    "type": "Memory Corruption",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "HTTP Response Splitting": [
                                {
                                    "id": 828,
                                    "host": "192.168.81.131",
                                    "service": "25/smtp",
                                    "description": "This script detects whether a host allows resuming SSL sessions by performing a full SSL handshake to receive a session ID, and then reconnecting with the previously used session ID.  If the server accepts the session ID in the second connection, the server maintains a cache of sessions that can be resumed. The remote host allows resuming SSL sessions.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSL Session Resume Supported",
                                    "type": "HTTP Response Splitting",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        }
                    },
                    "53/domain": {
                        "medium": {
                            "Denial of Service (DoS)": [
                                {
                                    "id": 852,
                                    "host": "192.168.81.131",
                                    "service": "53/domain",
                                    "description": "A denial of service (DoS) vulnerability exists in ISC BIND versions 9.11.18 / 9.11.18-S1 / 9.12.4-P2 / 9.13 / 9.14.11 / 9.15 / 9.16.2 / 9.17 / 9.17.1 and earlier. An unauthenticated, remote attacker can exploit this issue, via a specially-crafted message, to cause the service to stop responding.\n\nNote that Nessus has not tested for this issue but has instead relied only on the application's self-reported version number. The remote name server is affected by an assertion failure vulnerability.",
                                    "cvss": "5.0 Medium CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P",
                                    "solution": "Upgrade to the patched release most closely related to your current version of BIND.",
                                    "risk": "ISC BIND Denial of Service",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "https://kb.isc.org/docs/cve-2020-8617"
                                    ]
                                },
                                {
                                    "id": 853,
                                    "host": "192.168.81.131",
                                    "service": "53/domain",
                                    "description": "According to its self-reported version number, the installation of ISC BIND running on the remote name server is version 9.x prior to 9.11.22, 9.12.x prior to 9.16.6 or 9.17.x prior to 9.17.4. It is, therefore, affected by a denial of service (DoS) vulnerability due to an assertion failure when attempting to verify a truncated response to a TSIG-signed request. An authenticated, remote attacker can exploit this issue by sending a truncated response to a TSIG-signed request to trigger an assertion failure, causing the server to exit.\n\nNote that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   number. The remote name server is affected by a denial of service vulnerability.",
                                    "cvss": "4.0 Medium CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P",
                                    "solution": "Upgrade to BIND 9.11.22, 9.16.6, 9.17.4 or later.",
                                    "risk": "ISC BIND 9.x < 9.11.22, 9.12.x < 9.16.6, 9.17.x < 9.17.4 DoS",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "https://kb.isc.org/docs/cve-2020-8622"
                                    ]
                                },
                                {
                                    "id": 854,
                                    "host": "192.168.81.131",
                                    "service": "53/domain",
                                    "description": "According to its self-reported version, the instance of ISC BIND 9 running on the remote name server is affected by performance downgrade and Reflected DoS vulnerabilities. This is due to BIND DNS not sufficiently limiting the number fetches which may be performed while processing a referral response.\n\nAn unauthenticated, remote attacker can exploit this to cause degrade the service of the recursive server or to use the affected server as a reflector in a reflection attack. The remote name server is affected by Service Downgrade / Reflected DoS vulnerabilities.",
                                    "cvss": "5.0 Medium CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P",
                                    "solution": "Upgrade to the ISC BIND version referenced in the vendor advisory.",
                                    "risk": "ISC BIND Service Downgrade / Reflected DoS",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "https://kb.isc.org/docs/cve-2020-8616"
                                    ]
                                }
                            ]
                        },
                        "unknown": {
                            "Information Disclosure": [
                                {
                                    "id": 860,
                                    "host": "192.168.81.131",
                                    "service": "53/domain",
                                    "description": "This plugin is a SYN 'half-open' port scanner.  It shall be reasonably quick even against a firewalled target. \n\nNote that SYN scans are less intrusive than TCP (full connect) scans against broken services, but they might cause problems for less robust firewalls and also leave unclosed connections on the remote target, if the network is loaded. It is possible to determine which TCP ports are open.",
                                    "cvss": "unknown",
                                    "solution": "Protect your target with an IP filter.",
                                    "risk": "Nessus SYN scanner",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 855,
                                    "host": "192.168.81.131",
                                    "service": "53/domain",
                                    "description": "The remote host is running BIND or another DNS server that reports its version number when it receives a special request for the text 'version.bind' in the domain 'chaos'. \n\nThis version is not necessarily accurate and could even be forged, as some DNS servers send the information based on a configuration file. It is possible to obtain the version number of the remote DNS server.",
                                    "cvss": "unknown",
                                    "solution": "It is possible to hide the version number of BIND by using the 'version' directive in the 'options' section in named.conf.",
                                    "risk": "DNS Server BIND version Directive Remote Version Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 856,
                                    "host": "192.168.81.131",
                                    "service": "53/domain",
                                    "description": "Nessus was able to obtain version information by sending a special TXT record query to the remote host.\n\nNote that this version is not necessarily accurate and could even be forged, as some DNS servers send the information based on a configuration file. Nessus was able to obtain version information on the remote DNS server.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "DNS Server Version Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Denial of Service (DoS)": [
                                {
                                    "id": 857,
                                    "host": "192.168.81.131",
                                    "service": "53/domain",
                                    "description": "It is possible to learn the remote host name by querying the remote DNS server for 'hostname.bind' in the CHAOS domain. The DNS server discloses the remote host name.",
                                    "cvss": "unknown",
                                    "solution": "It may be possible to disable this feature.  Consult the vendor's documentation for more information.",
                                    "risk": "DNS Server hostname.bind Map Hostname Disclosure",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 858,
                                    "host": "192.168.81.131",
                                    "service": "53/domain",
                                    "description": "The remote service is a Domain Name System (DNS) server, which provides a mapping between hostnames and IP addresses. A DNS server is listening on the remote host.",
                                    "cvss": "unknown",
                                    "solution": "Disable this service if it is not needed or restrict access to internal hosts only if the service is available externally.",
                                    "risk": "DNS Server Detection",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "https://en.wikipedia.org/wiki/Domain_Name_System"
                                    ]
                                }
                            ],
                            "File Inclusion": [
                                {
                                    "id": 851,
                                    "host": "192.168.81.131",
                                    "service": "53/domain",
                                    "description": "unknown",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "unknown",
                                    "type": "File Inclusion",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        }
                    },
                    "80/http": {
                        "critical": {
                            "Execute arbitrary code on vulnerable system": [
                                {
                                    "id": 864,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "The \"Tiki Wiki CMS Groupware\" version on the remote host has reached the end of life.\n\nCPE:               cpe:/a:tiki:tikiwiki_cms/groupware:1.9.5\nInstalled version: 1.9.5\nLocation/URL:      http://192.168.81.131/tikiwiki\nEOL version:       1\nEOL date:          unknown\nEOL info:          https://tiki.org/Versions#Version_Lifecycle\n",
                                    "cvss": "10.0 High AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Update the Tiki Wiki CMS Groupware version on the remote host to a\n  still supported version.",
                                    "risk": "Tiki Wiki CMS Groupware End of Life (EOL) Detection",
                                    "type": "Execute arbitrary code on vulnerable system",
                                    "id_cve": [],
                                    "refs": [
                                        "https://tiki.org/Versions#Version_Lifecycle"
                                    ]
                                }
                            ],
                            "Information Disclosure": [
                                {
                                    "id": 865,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "Installed version: 01.Feb.2003\nFixed version:     4.2.4\n\n",
                                    "cvss": "10.0 High AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Upgrade to version 4.2.4 or later.",
                                    "risk": "TWiki XSS and Command Execution Vulnerabilities",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2008-5304"
                                    ],
                                    "refs": []
                                }
                            ]
                        },
                        "high": {
                            "Execute arbitrary code on vulnerable system": [
                                {
                                    "id": 866,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "In Tiki before 17.2, the user task component is vulnerable to a SQL Injection via the tiki-user_tasks.php show_history parameter.\n\nInstalled version: 1.9.5\nFixed version:     17.2\n\n",
                                    "cvss": "8.8 High CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                    "solution": "Upgrade to version 17.2 or later.",
                                    "risk": "Tiki Wiki CMS Groupware < 17.2 SQL Injection Vulnerability",
                                    "type": "Execute arbitrary code on vulnerable system",
                                    "id_cve": [
                                        "CVE-2018-20719"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ],
                            "Information Disclosure": [
                                {
                                    "id": 867,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "TikiWiki 21.2 allows templates to be edited without CSRF protection. This could allow an unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack and perform arbitrary actions on an affected system. The vulnerability is due to insufficient CSRF protections for the web-based management interface of the affected system. An attacker could exploit this vulnerability by persuading a user of the interface to follow a maliciously crafted link. A successful exploit could allow the attacker to perform arbitrary actions on an affected system with the privileges of the user. These action include allowing attackers to submit their own code through an authenticated user resulting in local file Inclusion. If an authenticated user who is able to edit TikiWiki templates visits an malicious website, template code can be edited.\n\nInstalled version: 1.9.5\nFixed version:     22\nInstallation\npath / port:       /tikiwiki\n\n",
                                    "cvss": "8.8 High CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                    "solution": "Update to version 22 which disables and hides the risky\n  preferences by default.",
                                    "risk": "Tiki Wiki < 22 Multiple Vulnerabilities",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2020-29254"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 870,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "The following files are calling the function phpinfo() which disclose potentially sensitive information:\n\nhttp://192.168.81.131/phpinfo.php\n",
                                    "cvss": "7.5 High AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                    "solution": "Delete the listed files or restrict access to them.",
                                    "risk": "phpinfo() output Reporting",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Gain Privileges": [
                                {
                                    "id": 868,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "The user_logout function in TikiWiki CMS/Groupware 4.x before 4.2 does not properly delete user login cookies, which allows remote attackers to gain access via cookie reuse.\n\nInstalled version: 1.9.5\nFixed version:     4.2\n\n",
                                    "cvss": "7.5 High AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                    "solution": "The vendor has released an advisory and fixes. Please see the\n  references for details.",
                                    "risk": "Tiki Wiki CMS Groupware < 4.2 Multiple Unspecified Vulnerabilities",
                                    "type": "Gain Privileges",
                                    "id_cve": [
                                        "CVE-2010-1135"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ],
                            "File Inclusion": [
                                {
                                    "id": 869,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "A vulnerability in Tiki Wiki CMS 15.2 could allow a remote attacker to read arbitrary files on a targeted system via a crafted pathname in a banner URL field.\n\nInstalled version: 1.9.5\nFixed version:     12.11\n\n",
                                    "cvss": "7.5 High CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "solution": "Upgrade to Tiki Wiki CMS Groupware version 12.11 LTS, 15.4 or\n  later.",
                                    "risk": "Tiki Wiki CMS Groupware 'fixedURLData' Local File Inclusion Vulnerability",
                                    "type": "File Inclusion",
                                    "id_cve": [
                                        "CVE-2016-10143"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ]
                        },
                        "medium": {
                            "HTTP Response Splitting": [
                                {
                                    "id": 883,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "protocol.c in the Apache HTTP Server 2.2.x through 2.2.21 does not properly restrict header information during construction of Bad Request (aka 400) error documents, which allows remote attackers to obtain the values of HTTPOnly cookies via vectors involving a (1) long or (2) malformed header in conjunction with crafted web script.\n\n",
                                    "cvss": "4.3 Medium AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "solution": "Update to Apache HTTP Server version 2.2.22 or later.",
                                    "risk": "Apache HTTP Server 'httpOnly' Cookie Information Disclosure Vulnerability",
                                    "type": "HTTP Response Splitting",
                                    "id_cve": [
                                        "CVE-2012-0053"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 876,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "The undocumented TRACK method in Microsoft Internet Information Services (IIS) 5.0 returns the content of the original request in the body of the response, which makes it easier for remote attackers to steal cookies and authentication credentials, or bypass the HttpOnly protection mechanism, by using TRACK to read the contents of the HTTP headers that are returned in the response, a technique that is similar to cross-site tracing (XST) using HTTP TRACE.\n\nThe web server has the following HTTP methods enabled: TRACE\n",
                                    "cvss": "5.8 Medium AV:N/AC:M/Au:N/C:P/I:P/A:N",
                                    "solution": "Disable the TRACE and TRACK methods in your web server\n  configuration.\n\n  Please see the manual of your web server or the references for more information.",
                                    "risk": "HTTP Debugging Methods (TRACE/TRACK) Enabled",
                                    "type": "HTTP Response Splitting",
                                    "id_cve": [
                                        "CVE-2003-1567"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 874,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "There is an Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) vulnerability in php webpages of Tiki-Wiki Groupware. Tiki-Wiki CMS all versions through 20.0 allows malicious users to cause the injection of malicious code fragments (scripts) into a legitimate web page.\n\nInstalled version: 1.9.5\nFixed version:     21.0\nInstallation\npath / port:       /tikiwiki\n\n",
                                    "cvss": "6.1 Medium CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                    "solution": "Update to version 21.0.",
                                    "risk": "Tiki Wiki CMS Groupware < 21.0 XSS Vulnerability",
                                    "type": "HTTP Response Splitting",
                                    "id_cve": [
                                        "CVE-2020-8966"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 882,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "Cross-site scripting (XSS) vulnerability in TikiWiki (Tiki) CMS/Groupware 2.2 allows remote attackers to inject arbitrary web script or HTML via the PHP_SELF portion of a URI to (1) tiki-galleries.php, (2) tiki-list_file_gallery.php, (3) tiki-listpages.php, and (4) tiki-orphan_pages.php.\n\nVulnerable URL: http://192.168.81.131/tikiwiki/tiki-listpages.php/<script>alert(\"XSS_Check\");</script>\n",
                                    "cvss": "4.3 Medium AV:N/AC:M/Au:N/C:N/I:P/A:N",
                                    "solution": "Upgrade to Tiki Wiki CMS Groupware version 2.4 or later.",
                                    "risk": "Tiki Wiki CMS Groupware Multiple Cross Site Scripting Vulnerabilities",
                                    "type": "HTTP Response Splitting",
                                    "id_cve": [
                                        "CVE-2009-1204"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ],
                            "Information Disclosure": [
                                {
                                    "id": 881,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "Apache HTTP Server could allow a remote attacker to obtain sensitive information. A remote attacker could obtain file inode numbers (i-numbers) from the ETag header, if the server is configured to use the FileETag directive, and the PIDs of child processes when Apache HTTP server generates MIME message boundaries. An attacker could then use this information to launch further attacks against the affected server.\n\nApache HTTP Server 1.3.22 through 1.3.27 on OpenBSD allows remote attackers to obtain sensitive information via (1) the ETag header, which reveals the inode number, or (2) multipart MIME boundary, which reveals child process IDs (PID).\n\nInformation that was gathered:\nInode: 67575\nSize: 45\n\n",
                                    "cvss": "4.3 Medium AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "solution": "For OpenBSD 3.2:\nApply the patch for this vulnerability, as listed in OpenBSD 3.2 errata 008: SECURITY FIX: February 25, 2003. See References.. Maggiori info (https://exchange.xforce.ibmcloud.com/vulnerabilities/11438)\n\nOpenBSD has released a patch that addresses this issue.\n  Inode numbers returned from the server are now encoded using a private hash to avoid the\n  release of sensitive information.\n\n  Novell has released TID10090670 to advise users to apply the available workaround of\n  disabling the directive in the configuration file for Apache releases on NetWare. Please\n  see the attached Technical Information Document for further details.",
                                    "risk": "Apache HTTP Server ETag Header Information Disclosure Weakness",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2003-1418"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 872,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "Tiki before 21.2 allows XSS because [\\s\\/\"\\'] is not properly considered in lib/core/TikiFilter/PreventXss.php.\n\nInstalled version: 1.9.5\nFixed version:     21.2\nInstallation\npath / port:       /tikiwiki\n\n",
                                    "cvss": "6.1 Medium CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                    "solution": "Update to version 21.2.",
                                    "risk": "Tiki Wiki < 21.2 XSS Vulnerability",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2020-16131"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 877,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "tiki/tiki-upload_file.php in Tiki 18.4 allows remote attackers to upload JavaScript code that is executed upon visiting a tiki/tiki-download_file.php?display&amp;fileId= URI.\n\nInstalled version: 1.9.5\nFixed version:     None\nInstallation\npath / port:       /tikiwiki\n\n",
                                    "cvss": "5.4 Medium CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
                                    "solution": "No known solution was made available for at least one year since the disclosure\n  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer\n  release, disable respective features, remove the product or replace the product by another one.",
                                    "risk": "Tiki Wiki CMS Groupware 18.4 XSS Vulnerability",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2019-15314"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 878,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "An XSS vulnerability (via an SVG image) in Tiki before 18 allows an authenticated user to gain administrator privileges if an administrator opens a wiki page with a malicious SVG image, related to lib/filegals/filegallib.php.\n\nInstalled version: 1.9.5\nFixed version:     18.0\n\n",
                                    "cvss": "5.4 Medium CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
                                    "solution": "Upgrade to version 18.0 or later.",
                                    "risk": "Tiki Wiki CMS Groupware XSS Vulnerability",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2018-7188"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 880,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "The following input fields where identified (URL:input name):\n\nhttp://192.168.81.131/twiki/bin/view/TWiki/TWikiUserAuthentication:oldpassword\n",
                                    "cvss": "4.8 Medium AV:A/AC:L/Au:N/C:P/I:P/A:N",
                                    "solution": "Enforce the transmission of sensitive data via an encrypted SSL/TLS connection.\n  Additionally make sure the host / application is redirecting all users to the secured SSL/TLS connection before\n  allowing to input sensitive data into the mentioned functions.",
                                    "risk": "Cleartext Transmission of Sensitive Information via HTTP",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.owasp.org/index.php/Top_10_2013-A2-Broken_Authentication_and_Session_Management"
                                    ]
                                },
                                {
                                    "id": 886,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "The remote web server is affected by an information disclosure vulnerability due to the ETag header providing sensitive information that could aid an attacker, such as the inode number of requested files. The remote web server is affected by an information disclosure vulnerability.",
                                    "cvss": "4.3 Medium CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "solution": "Modify the HTTP ETag header of the web server to not include file inodes in the ETag header calculation. Refer to the linked Apache documentation for more information.",
                                    "risk": "Apache Server ETag Header Information Disclosure",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "http://httpd.apache.org/docs/2.2/mod/core.html#FileETag"
                                    ]
                                },
                                {
                                    "id": 890,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "The remote web server supports the TRACE and/or TRACK methods. TRACE and TRACK are HTTP methods that are used to debug web server connections. Debugging functions are enabled on the remote web server.",
                                    "cvss": "5.0 Medium CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N",
                                    "solution": "Disable these HTTP methods. Refer to the plugin output for more information.",
                                    "risk": "HTTP TRACE / TRACK Methods Allowed",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.cgisecurity.com/whitehat-mirror/WH-WhitePaper_XST_ebook.pdf",
                                        "http://www.apacheweek.com/issues/03-01-24",
                                        "https://download.oracle.com/sunalerts/1000718.1.html"
                                    ]
                                }
                            ],
                            "Cross Site Request Forgery (CSRF)": [
                                {
                                    "id": 871,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "Cross-site request forgery (CSRF) vulnerability in TWiki before 4.3.2 allows remote attackers to hijack the authentication of arbitrary users for requests that update pages, as demonstrated by a URL for a save script in the ACTION attribute of a FORM element, in conjunction with a call to the submit method in the onload attribute of a BODY element.  NOTE: this issue exists because of an insufficient fix for CVE-2009-1339.\n\nInstalled version: 01.Feb.2003\nFixed version:     4.3.2\n\n",
                                    "cvss": "6.8 Medium AV:N/AC:M/Au:N/C:P/I:P/A:P",
                                    "solution": "Upgrade to TWiki version 4.3.2 or later.",
                                    "risk": "TWiki Cross-Site Request Forgery Vulnerability - Sep10",
                                    "type": "Cross Site Request Forgery (CSRF)",
                                    "id_cve": [
                                        "CVE-2009-4898"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 875,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "Cross-site request forgery (CSRF) vulnerability in TWiki before 4.3.1 allows remote authenticated users to hijack the authentication of arbitrary users for requests that update pages, as demonstrated by a URL for a save script in the SRC attribute of an IMG element, a related issue to CVE-2009-1434.\n\nInstalled version: 01.Feb.2003\nFixed version:     4.3.1\n\n",
                                    "cvss": "6.0 Medium AV:N/AC:M/Au:S/C:P/I:P/A:P",
                                    "solution": "Upgrade to version 4.3.1 or later.",
                                    "risk": "TWiki Cross-Site Request Forgery Vulnerability",
                                    "type": "Cross Site Request Forgery (CSRF)",
                                    "id_cve": [
                                        "CVE-2009-1339"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ],
                            "Cross Site Scripting (XSS)": [
                                {
                                    "id": 873,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "bin/statistics in TWiki 6.0.2 allows cross-site scripting (XSS) via the webs parameter.\n\nInstalled version: 01.Feb.2003\nFixed version:     6.1.0\n\n",
                                    "cvss": "6.1 Medium CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                    "solution": "Update to version 6.1.0 or later.",
                                    "risk": "TWiki < 6.1.0 XSS Vulnerability",
                                    "type": "Cross Site Scripting (XSS)",
                                    "id_cve": [
                                        "CVE-2018-20212"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ],
                            "Denial of Service (DoS)": [
                                {
                                    "id": 879,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "Unspecified vulnerability in Tikiwiki before 2.2 has unknown impact and attack vectors related to \"size of user-provided input,\" a different issue than CVE-2008-3653.\n\nInstalled version: 1.9.5\nFixed version:     2.2\n\n",
                                    "cvss": "5.0 Medium AV:N/AC:L/Au:N/C:N/I:P/A:N",
                                    "solution": "Upgrade to version 2.2 or later.",
                                    "risk": "Tiki Wiki CMS Groupware Input Sanitation Weakness Vulnerability",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [
                                        "CVE-2008-5318"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ]
                        },
                        "low": {
                            "Execute arbitrary code on vulnerable system": [
                                {
                                    "id": 866,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "In Tiki before 17.2, the user task component is vulnerable to a SQL Injection via the tiki-user_tasks.php show_history parameter.\n\nInstalled version: 1.9.5\nFixed version:     17.2\n\n",
                                    "cvss": "8.8 High CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                    "solution": "Upgrade to version 17.2 or later.",
                                    "risk": "Tiki Wiki CMS Groupware < 17.2 SQL Injection Vulnerability",
                                    "type": "Execute arbitrary code on vulnerable system",
                                    "id_cve": [
                                        "CVE-2018-20719"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ],
                            "Information Disclosure": [
                                {
                                    "id": 867,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "TikiWiki 21.2 allows templates to be edited without CSRF protection. This could allow an unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack and perform arbitrary actions on an affected system. The vulnerability is due to insufficient CSRF protections for the web-based management interface of the affected system. An attacker could exploit this vulnerability by persuading a user of the interface to follow a maliciously crafted link. A successful exploit could allow the attacker to perform arbitrary actions on an affected system with the privileges of the user. These action include allowing attackers to submit their own code through an authenticated user resulting in local file Inclusion. If an authenticated user who is able to edit TikiWiki templates visits an malicious website, template code can be edited.\n\nInstalled version: 1.9.5\nFixed version:     22\nInstallation\npath / port:       /tikiwiki\n\n",
                                    "cvss": "8.8 High CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                    "solution": "Update to version 22 which disables and hides the risky\n  preferences by default.",
                                    "risk": "Tiki Wiki < 22 Multiple Vulnerabilities",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2020-29254"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 872,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "Tiki before 21.2 allows XSS because [\\s\\/\"\\'] is not properly considered in lib/core/TikiFilter/PreventXss.php.\n\nInstalled version: 1.9.5\nFixed version:     21.2\nInstallation\npath / port:       /tikiwiki\n\n",
                                    "cvss": "6.1 Medium CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                    "solution": "Update to version 21.2.",
                                    "risk": "Tiki Wiki < 21.2 XSS Vulnerability",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2020-16131"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 877,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "tiki/tiki-upload_file.php in Tiki 18.4 allows remote attackers to upload JavaScript code that is executed upon visiting a tiki/tiki-download_file.php?display&amp;fileId= URI.\n\nInstalled version: 1.9.5\nFixed version:     None\nInstallation\npath / port:       /tikiwiki\n\n",
                                    "cvss": "5.4 Medium CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
                                    "solution": "No known solution was made available for at least one year since the disclosure\n  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer\n  release, disable respective features, remove the product or replace the product by another one.",
                                    "risk": "Tiki Wiki CMS Groupware 18.4 XSS Vulnerability",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2019-15314"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 878,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "An XSS vulnerability (via an SVG image) in Tiki before 18 allows an authenticated user to gain administrator privileges if an administrator opens a wiki page with a malicious SVG image, related to lib/filegals/filegallib.php.\n\nInstalled version: 1.9.5\nFixed version:     18.0\n\n",
                                    "cvss": "5.4 Medium CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
                                    "solution": "Upgrade to version 18.0 or later.",
                                    "risk": "Tiki Wiki CMS Groupware XSS Vulnerability",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2018-7188"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ],
                            "File Inclusion": [
                                {
                                    "id": 869,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "A vulnerability in Tiki Wiki CMS 15.2 could allow a remote attacker to read arbitrary files on a targeted system via a crafted pathname in a banner URL field.\n\nInstalled version: 1.9.5\nFixed version:     12.11\n\n",
                                    "cvss": "7.5 High CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "solution": "Upgrade to Tiki Wiki CMS Groupware version 12.11 LTS, 15.4 or\n  later.",
                                    "risk": "Tiki Wiki CMS Groupware 'fixedURLData' Local File Inclusion Vulnerability",
                                    "type": "File Inclusion",
                                    "id_cve": [
                                        "CVE-2016-10143"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ],
                            "Cross Site Scripting (XSS)": [
                                {
                                    "id": 873,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "bin/statistics in TWiki 6.0.2 allows cross-site scripting (XSS) via the webs parameter.\n\nInstalled version: 01.Feb.2003\nFixed version:     6.1.0\n\n",
                                    "cvss": "6.1 Medium CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                    "solution": "Update to version 6.1.0 or later.",
                                    "risk": "TWiki < 6.1.0 XSS Vulnerability",
                                    "type": "Cross Site Scripting (XSS)",
                                    "id_cve": [
                                        "CVE-2018-20212"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ],
                            "HTTP Response Splitting": [
                                {
                                    "id": 874,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "There is an Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) vulnerability in php webpages of Tiki-Wiki Groupware. Tiki-Wiki CMS all versions through 20.0 allows malicious users to cause the injection of malicious code fragments (scripts) into a legitimate web page.\n\nInstalled version: 1.9.5\nFixed version:     21.0\nInstallation\npath / port:       /tikiwiki\n\n",
                                    "cvss": "6.1 Medium CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                    "solution": "Update to version 21.0.",
                                    "risk": "Tiki Wiki CMS Groupware < 21.0 XSS Vulnerability",
                                    "type": "HTTP Response Splitting",
                                    "id_cve": [
                                        "CVE-2020-8966"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ]
                        },
                        "info": {
                            "Execute arbitrary code on vulnerable system": [
                                {
                                    "id": 864,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "The \"Tiki Wiki CMS Groupware\" version on the remote host has reached the end of life.\n\nCPE:               cpe:/a:tiki:tikiwiki_cms/groupware:1.9.5\nInstalled version: 1.9.5\nLocation/URL:      http://192.168.81.131/tikiwiki\nEOL version:       1\nEOL date:          unknown\nEOL info:          https://tiki.org/Versions#Version_Lifecycle\n",
                                    "cvss": "10.0 High AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Update the Tiki Wiki CMS Groupware version on the remote host to a\n  still supported version.",
                                    "risk": "Tiki Wiki CMS Groupware End of Life (EOL) Detection",
                                    "type": "Execute arbitrary code on vulnerable system",
                                    "id_cve": [],
                                    "refs": [
                                        "https://tiki.org/Versions#Version_Lifecycle"
                                    ]
                                }
                            ],
                            "Information Disclosure": [
                                {
                                    "id": 865,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "Installed version: 01.Feb.2003\nFixed version:     4.2.4\n\n",
                                    "cvss": "10.0 High AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Upgrade to version 4.2.4 or later.",
                                    "risk": "TWiki XSS and Command Execution Vulnerabilities",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2008-5304"
                                    ],
                                    "refs": []
                                }
                            ]
                        },
                        "unknown": {
                            "Denial of Service (DoS)": [
                                {
                                    "id": 893,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "Nessus was able to identify the remote service by its banner or by looking at the error message it sends when it receives an HTTP request. The remote service could be identified.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Service Detection",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 861,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "The byterange filter in the Apache HTTP Server 1.3.x, 2.0.x through 2.0.64, and 2.2.x through 2.2.19 allows remote attackers to cause a denial of service (memory and CPU consumption) via a Range header that expresses multiple overlapping ranges, as exploited in the wild in August 2011, a different vulnerability than CVE-2007-0086.\n\nThe Apache web server is vulnerable to a denial of service attack when numerous\noverlapping byte ranges are requested.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "http-server-header",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192",
                                        "https://www.securityfocus.com/bid/49303",
                                        "https://www.tenable.com/plugins/nessus/55976",
                                        "https://seclists.org/fulldisclosure/2011/Aug/175"
                                    ],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 884,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "Security patches may have been 'backported' to the remote HTTP server without changing its version number.\n\nBanner-based checks have been disabled to avoid false positives.\n\nNote that this test is informational only and does not denote any security problem. Security patches are backported.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Backported Security Patch Detection (WWW)",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "https://access.redhat.com/security/updates/backporting/?sc_cid=3093"
                                    ]
                                },
                                {
                                    "id": 888,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "This test gives some information about the remote HTTP protocol - the version used, whether HTTP Keep-Alive and HTTP pipelining are enabled, etc... \n\nThis test is informational only and does not denote any security problem. Some information about the remote HTTP configuration can be extracted.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "HyperText Transfer Protocol (HTTP) Information",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Information Disclosure": [
                                {
                                    "id": 894,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "This plugin is a SYN 'half-open' port scanner.  It shall be reasonably quick even against a firewalled target. \n\nNote that SYN scans are less intrusive than TCP (full connect) scans against broken services, but they might cause problems for less robust firewalls and also leave unclosed connections on the remote target, if the network is loaded. It is possible to determine which TCP ports are open.",
                                    "cvss": "unknown",
                                    "solution": "Protect your target with an IP filter.",
                                    "risk": "Nessus SYN scanner",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 885,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "Security patches may have been 'backported' to the remote PHP install without changing its version number.\n\nBanner-based checks have been disabled to avoid false positives.\n\nNote that this test is informational only and does not denote any security problem. Security patches have been backported.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Backported Security Patch Detection (PHP)",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://access.redhat.com/security/updates/backporting/?sc_cid=3093"
                                    ]
                                },
                                {
                                    "id": 887,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "The remote host is running the Apache HTTP Server, an open source web server. It was possible to read the version number from the banner. It is possible to obtain the version number of the remote Apache HTTP server.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Apache HTTP Server Version",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://httpd.apache.org/"
                                    ]
                                },
                                {
                                    "id": 889,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "Nessus was able to determine the version of PHP available on the remote web server. It was possible to obtain the version number of the remote PHP installation.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "PHP Version Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 892,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "By calling the OPTIONS method, it is possible to determine which HTTP methods are allowed on each directory.\n\nThe following HTTP methods are considered insecure:\n  PUT, DELETE, CONNECT, TRACE, HEAD\n\nMany frameworks and languages treat 'HEAD' as a 'GET' request, albeit one without any body in the response. If a security constraint was set on 'GET' requests such that only 'authenticatedUsers' could access GET requests for a particular servlet or resource, it would be bypassed for the 'HEAD' version. This allowed unauthorized blind submission of any privileged GET request.\n\nAs this list may be incomplete, the plugin also tests - if 'Thorough tests' are enabled or 'Enable web applications tests' is set to 'yes' in the scan policy - various known HTTP methods on each directory and considers them as unsupported if it receives a response code of 400, 403, 405, or 501.\n\nNote that the plugin output is only informational and does not necessarily indicate the presence of any security vulnerabilities. This plugin determines which HTTP methods are allowed on various CGI directories.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "HTTP Methods Allowed (per directory)",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.nessus.org/u?d9c03a9a",
                                        "http://www.nessus.org/u?b019cbdb",
                                        "https://www.owasp.org/index.php/Test_HTTP_Methods_(OTG-CONFIG-006)"
                                    ]
                                }
                            ],
                            "Execute arbitrary code on vulnerable system": [
                                {
                                    "id": 891,
                                    "host": "192.168.81.131",
                                    "service": "80/http",
                                    "description": "This plugin attempts to determine the type and the version of the   remote web server. A web server is running on the remote host.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "HTTP Server Type and Version",
                                    "type": "Execute arbitrary code on vulnerable system",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        }
                    },
                    "139/netbios-ssn": {
                        "unknown": {
                            "Information Disclosure": [
                                {
                                    "id": 896,
                                    "host": "192.168.81.131",
                                    "service": "139/netbios-ssn",
                                    "description": "This plugin is a SYN 'half-open' port scanner.  It shall be reasonably quick even against a firewalled target. \n\nNote that SYN scans are less intrusive than TCP (full connect) scans against broken services, but they might cause problems for less robust firewalls and also leave unclosed connections on the remote target, if the network is loaded. It is possible to determine which TCP ports are open.",
                                    "cvss": "unknown",
                                    "solution": "Protect your target with an IP filter.",
                                    "risk": "Nessus SYN scanner",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 897,
                                    "host": "192.168.81.131",
                                    "service": "139/netbios-ssn",
                                    "description": "The remote service understands the CIFS (Common Internet File System) or Server Message Block (SMB) protocol, used to provide shared access to files, printers, etc between nodes on a network. A file / print sharing service is listening on the remote host.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Microsoft Windows SMB Service Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "File Inclusion": [
                                {
                                    "id": 895,
                                    "host": "192.168.81.131",
                                    "service": "139/netbios-ssn",
                                    "description": "unknown",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "unknown",
                                    "type": "File Inclusion",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        }
                    },
                    "445/netbios-ssn": {
                        "unknown": {
                            "File Inclusion": [
                                {
                                    "id": 898,
                                    "host": "192.168.81.131",
                                    "service": "445/netbios-ssn",
                                    "description": "unknown",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "unknown",
                                    "type": "File Inclusion",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        }
                    },
                    "3306/mysql": {
                        "critical": {
                            "Gain Privileges": [
                                {
                                    "id": 900,
                                    "host": "192.168.81.131",
                                    "service": "3306/mysql",
                                    "description": "It was possible to login as root with password \"root\".\n\n\n",
                                    "cvss": "9.0 High AV:N/AC:L/Au:N/C:C/I:P/A:P",
                                    "solution": "Change the password as soon as possible.",
                                    "risk": "MySQL / MariaDB weak password",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        },
                        "unknown": {
                            "Information Disclosure": [
                                {
                                    "id": 903,
                                    "host": "192.168.81.131",
                                    "service": "3306/mysql",
                                    "description": "This plugin is a SYN 'half-open' port scanner.  It shall be reasonably quick even against a firewalled target. \n\nNote that SYN scans are less intrusive than TCP (full connect) scans against broken services, but they might cause problems for less robust firewalls and also leave unclosed connections on the remote target, if the network is loaded. It is possible to determine which TCP ports are open.",
                                    "cvss": "unknown",
                                    "solution": "Protect your target with an IP filter.",
                                    "risk": "Nessus SYN scanner",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Denial of Service (DoS)": [
                                {
                                    "id": 901,
                                    "host": "192.168.81.131",
                                    "service": "3306/mysql",
                                    "description": "The remote host is running MySQL, an open source database server. A database server is listening on the remote port.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "MySQL Server Detection",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 902,
                                    "host": "192.168.81.131",
                                    "service": "3306/mysql",
                                    "description": "It was possible to identify the remote service by its banner or by looking at the error message it sends when it receives a 'HELP' request. The remote service could be identified.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Service Detection (HELP Request)",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "File Inclusion": [
                                {
                                    "id": 899,
                                    "host": "192.168.81.131",
                                    "service": "3306/mysql",
                                    "description": "unknown",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "ssl-ccs-injection",
                                    "type": "File Inclusion",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        }
                    },
                    "3632/distccd": {
                        "critical": {
                            "Information Disclosure": [
                                {
                                    "id": 904,
                                    "host": "192.168.81.131",
                                    "service": "3632/distccd",
                                    "description": "distcc 2.x, as used in XCode 1.5 and others, when not configured to restrict access to the server port, allows remote attackers to execute arbitrary commands via compilation jobs, which are executed by the server without authorization checks.\n\nAllows executing of arbitrary commands on systems running distccd 3.1 and\nearlier. The vulnerability is the consequence of weak service configuration.\n",
                                    "cvss": "9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)",
                                    "solution": "n/a",
                                    "risk": "distcc-cve2004-2687",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687",
                                        "https://nvd.nist.gov/vuln/detail/CVE-2004-2687",
                                        "https://distcc.github.io/security.html"
                                    ],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ]
                        }
                    },
                    "5432/postgresql": {
                        "critical": {
                            "Information Disclosure": [
                                {
                                    "id": 917,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The remote service accepts connections encrypted using SSL 2.0 and/or SSL 3.0. These versions of SSL are affected by several cryptographic flaws, including:\n\n  - An insecure padding scheme with CBC ciphers.\n\n  - Insecure session renegotiation and resumption schemes.\n\nAn attacker can exploit these flaws to conduct man-in-the-middle attacks or to decrypt communications between the affected service and clients.\n\nAlthough SSL/TLS has a secure means for choosing the highest supported version of the protocol (so that these versions will be used only if the client or server support nothing better), many web browsers implement this in an unsafe way that allows an attacker to downgrade a connection (such as in POODLE). Therefore, it is recommended that these protocols be disabled entirely.\n\nNIST has determined that SSL 3.0 is no longer acceptable for secure communications. As of the date of enforcement found in PCI DSS v3.1, any version of SSL will not meet the PCI SSC's definition of 'strong cryptography'. The remote service encrypts traffic using a protocol with known weaknesses.",
                                    "cvss": "10.0 High CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Consult the application's documentation to disable SSL 2.0 and 3.0.\nUse TLS 1.2 (with approved cipher suites) or higher instead.",
                                    "risk": "SSL Version 2 and 3 Protocol Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.schneier.com/academic/paperfiles/paper-ssl.pdf",
                                        "http://www.nessus.org/u?b06c7e95",
                                        "http://www.nessus.org/u?247c4540",
                                        "https://www.openssl.org/~bodo/ssl-poodle.pdf",
                                        "http://www.nessus.org/u?5d15ba70",
                                        "https://www.imperialviolet.org/2014/10/14/poodle.html",
                                        "https://tools.ietf.org/html/rfc7507",
                                        "https://tools.ietf.org/html/rfc7568"
                                    ]
                                }
                            ],
                            "Gain Privileges": [
                                {
                                    "id": 930,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The remote x509 certificate on the remote SSL server has been generated on a Debian or Ubuntu system which contains a bug in the random number generator of its OpenSSL library. \n\nThe problem is due to a Debian packager removing nearly all sources of entropy in the remote version of OpenSSL. \n\nAn attacker can easily obtain the private part of the remote key and use this to decipher the remote session or set up a man in the middle attack. The remote SSL certificate uses a weak key.",
                                    "cvss": "10.0 High CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Consider all cryptographic material generated on the remote host to be guessable.  In particuliar, all SSH, SSL and OpenVPN key material should be re-generated.",
                                    "risk": "Debian OpenSSH/OpenSSL Package Random Number Generator Weakness (SSL check)",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.nessus.org/u?107f9bdc",
                                        "http://www.nessus.org/u?f14f4224"
                                    ]
                                },
                                {
                                    "id": 906,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "It was possible to login as user postgres with password \"postgres\".\n\n\n",
                                    "cvss": "9.0 High AV:N/AC:L/Au:N/C:C/I:P/A:P",
                                    "solution": "Change the password as soon as possible.",
                                    "risk": "PostgreSQL weak password",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        },
                        "high": {
                            "Information Disclosure": [
                                {
                                    "id": 907,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other products, uses nondeterministic CBC padding, which makes it easier for man-in-the-middle attackers to obtain cleartext data via a padding-oracle attack, aka the \"POODLE\" issue.\n\nOpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly restrict processing of ChangeCipherSpec messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive information, via a crafted TLS handshake, aka the \"CCS Injection\" vulnerability.\n\n",
                                    "cvss": "7.4 High CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                    "solution": "Updates are available. Please see the references for more information.",
                                    "risk": "SSL/TLS: OpenSSL CCS Man in the Middle Security Bypass Vulnerability",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2014-0224",
                                        "CVE-2014-3566"
                                    ],
                                    "refs": [],
                                    "exploits": [
                                        null
                                    ],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ]
                        },
                        "medium": {
                            "Information Disclosure": [
                                {
                                    "id": 909,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The remote SSL/TLS server is using the following certificate(s) with a RSA key with less than 2048 bits (public-key-size:public-key-algorithm:serial:issuer):\n\n1024:RSA:00FAF93A4C7FB6B9CC:1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX (Server certificate)\n",
                                    "cvss": "5.3 Medium CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "solution": "Replace the certificate with a stronger key and reissue the\n  certificates it signed.",
                                    "risk": "SSL/TLS: Server Certificate / Certificate in Chain with RSA keys less than 2048 bits",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.cabforum.org/wp-content/uploads/Baseline_Requirements_V1.pdf"
                                    ]
                                },
                                {
                                    "id": 910,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The certificate of the remote service expired on 2010-04-16 14:07:45.\n\nCertificate details:\nfingerprint (SHA-1)             | ED093088706603BFD5DC237399B498DA2D4D31C6\nfingerprint (SHA-256)           | E7A7FA0D63E457C7C4A59B38B70849C6A70BDA6F830C7AF1E32DEE436DE813CC\nissued by                       | 1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX\npublic key algorithm            | RSA\npublic key size (bits)          | 1024\nserial                          | 00FAF93A4C7FB6B9CC\nsignature algorithm             | sha1WithRSAEncryption\nsubject                         | 1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX\nsubject alternative names (SAN) | None\nvalid from                      | 2010-03-17 14:07:45 UTC\nvalid until                     | 2010-04-16 14:07:45 UTC\n",
                                    "cvss": "5.0 Medium AV:N/AC:L/Au:N/C:N/I:P/A:N",
                                    "solution": "Replace the SSL/TLS certificate by a new one.",
                                    "risk": "SSL/TLS: Certificate Expired",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 912,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The SSL protocol, as used in certain configurations in Microsoft Windows and Microsoft Internet Explorer, Mozilla Firefox, Google Chrome, Opera, and other products, encrypts data by using CBC mode with chained initialization vectors, which allows man-in-the-middle attackers to obtain plaintext HTTP headers via a blockwise chosen-boundary attack (BCBA) on an HTTPS session, in conjunction with JavaScript code that uses (1) the HTML5 WebSocket API, (2) the Java URLConnection API, or (3) the Silverlight WebClient API, aka a \"BEAST\" attack.\n\nThe service is only providing the deprecated TLSv1.0 protocol and supports one or more ciphers. Those supported ciphers can be found in the 'SSL/TLS: Report Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.802067) VT.\n",
                                    "cvss": "4.3 Medium AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "solution": "It is recommended to disable the deprecated TLSv1.0 and/or\n  TLSv1.1 protocols in favor of the TLSv1.2+ protocols. Please see the references for more\n  information.",
                                    "risk": "SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2011-3389"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 913,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The following certificates are part of the certificate chain but using insecure signature algorithms:\n\nSubject:              1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX\nSignature Algorithm:  sha1WithRSAEncryption\n\n\n",
                                    "cvss": "4.0 Medium AV:N/AC:H/Au:N/C:P/I:P/A:N",
                                    "solution": "Servers that use SSL/TLS certificates signed with a weak SHA-1, MD5, MD4 or MD2 hashing algorithm will need to obtain new\n  SHA-2 signed SSL/TLS certificates to avoid web browser SSL/TLS certificate warnings.",
                                    "risk": "SSL/TLS: Certificate Signed Using A Weak Signature Algorithm",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://blog.mozilla.org/security/2014/09/23/phasing-out-certificates-with-sha-1-based-signature-algorithms/"
                                    ]
                                },
                                {
                                    "id": 908,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and other products, requires a server to send a ServerVerify message before establishing that a client possesses certain plaintext RSA data, which makes it easier for remote attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding oracle, aka a \"DROWN\" attack.\n\nIn addition to TLSv1.0+ the service is also providing the deprecated SSLv3 protocol and supports one or more ciphers. Those supported ciphers can be found in the 'SSL/TLS: Report Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.802067) VT.\n",
                                    "cvss": "5.9 Medium CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "solution": "It is recommended to disable the deprecated SSLv2 and/or SSLv3\n  protocols in favor of the TLSv1.2+ protocols. Please see the references for more information.",
                                    "risk": "SSL/TLS: Deprecated SSLv2 and SSLv3 Protocol Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2016-0800"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 911,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The RC4 algorithm, as used in the TLS protocol and SSL protocol, has many single-byte biases, which makes it easier for remote attackers to conduct plaintext-recovery attacks via statistical analysis of ciphertext in a large number of sessions that use the same plaintext.\n\n'Weak' cipher suites accepted by this service via the SSLv3 protocol:\n\nTLS_RSA_WITH_RC4_128_SHA\n\n'Weak' cipher suites accepted by this service via the TLSv1.0 protocol:\n\nTLS_RSA_WITH_RC4_128_SHA\n\n\n",
                                    "cvss": "5.0 Medium AV:N/AC:L/Au:N/C:P/I:N/A:N",
                                    "solution": "The configuration of this services should be changed so\n  that it does not accept the listed weak cipher suites anymore.\n\n  Please see the references for more resources supporting you with this task.",
                                    "risk": "SSL/TLS: Report Weak Cipher Suites",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2013-2566"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 918,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The remote host supports the use of RC4 in one or more cipher suites.\nThe RC4 cipher is flawed in its generation of a pseudo-random stream of bytes so that a wide variety of small biases are introduced into the stream, decreasing its randomness.\n\nIf plaintext is repeatedly encrypted (e.g., HTTP cookies), and an attacker is able to obtain many (i.e., tens of millions) ciphertexts, the attacker may be able to derive the plaintext. The remote service supports the use of the RC4 cipher.",
                                    "cvss": "4.3 Medium CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "solution": "Reconfigure the affected application, if possible, to avoid use of RC4 ciphers. Consider using TLS 1.2 with AES-GCM suites subject to browser and web server support.",
                                    "risk": "SSL RC4 Cipher Suites Supported (Bar Mitzvah)",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.rc4nomore.com/",
                                        "http://www.nessus.org/u?ac7327a0",
                                        "http://cr.yp.to/talks/2013.03.12/slides.pdf",
                                        "http://www.isg.rhul.ac.uk/tls/",
                                        "https://www.imperva.com/docs/HII_Attacking_SSL_when_using_RC4.pdf"
                                    ]
                                },
                                {
                                    "id": 920,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The remote host is affected by a man-in-the-middle (MitM) information disclosure vulnerability known as POODLE. The vulnerability is due to the way SSL 3.0 handles padding bytes when decrypting messages encrypted using block ciphers in cipher block chaining (CBC) mode.\nMitM attackers can decrypt a selected byte of a cipher text in as few as 256 tries if they are able to force a victim application to repeatedly send the same data over newly created SSL 3.0 connections.\n\nAs long as a client and service both support SSLv3, a connection can be 'rolled back' to SSLv3, even if TLSv1 or newer is supported by the client and service.\n\nThe TLS Fallback SCSV mechanism prevents 'version rollback' attacks without impacting legacy clients; however, it can only protect connections when the client and service support the mechanism. Sites that cannot disable SSLv3 immediately should enable this mechanism.\n\nThis is a vulnerability in the SSLv3 specification, not in any particular SSL implementation. Disabling SSLv3 is the only way to completely mitigate the vulnerability. It is possible to obtain sensitive information from the remote host with SSL/TLS-enabled services.",
                                    "cvss": "4.3 Medium CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N",
                                    "solution": "Disable SSLv3.\n\nServices that must support SSLv3 should enable the TLS Fallback SCSV mechanism until SSLv3 can be disabled.",
                                    "risk": "SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.imperialviolet.org/2014/10/14/poodle.html",
                                        "https://www.openssl.org/~bodo/ssl-poodle.pdf",
                                        "https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00"
                                    ]
                                },
                                {
                                    "id": 923,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The remote service accepts connections encrypted using TLS 1.0. TLS 1.0 has a number of cryptographic design flaws. Modern implementations of TLS 1.0 mitigate these problems, but newer versions of TLS like 1.2 and 1.3 are designed against these flaws and should be used whenever possible.\n\nAs of March 31, 2020, Endpoints that aren’t enabled for TLS 1.2 and higher will no longer function properly with major web browsers and major vendors.\n\nPCI DSS v3.2 requires that TLS 1.0 be disabled entirely by June 30, 2018, except for POS POI terminals (and the SSL/TLS termination points to which they connect) that can be verified as not being susceptible to any known exploits. The remote service encrypts traffic using an older version of TLS.",
                                    "cvss": "6.1 Medium CVSS2#AV:N/AC:H/Au:N/C:C/I:P/A:N",
                                    "solution": "Enable support for TLS 1.2 and 1.3, and disable support for TLS 1.0.",
                                    "risk": "TLS Version 1.0 Protocol Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://tools.ietf.org/html/draft-ietf-tls-oldversions-deprecate-00"
                                    ]
                                },
                                {
                                    "id": 928,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The X.509 certificate chain for this service is not signed by a recognized certificate authority.  If the remote host is a public host in production, this nullifies the use of SSL as anyone could establish a man-in-the-middle attack against the remote host. \n\nNote that this plugin does not check for certificate chains that end in a certificate that is not self-signed, but is signed by an unrecognized certificate authority. The SSL certificate chain for this service ends in an unrecognized self-signed certificate.",
                                    "cvss": "6.4 Medium CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N",
                                    "solution": "Purchase or generate a proper SSL certificate for this service.",
                                    "risk": "SSL Self-Signed Certificate",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 929,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "This plugin checks expiry dates of certificates associated with SSL- enabled services on the target and reports whether any have already expired. The remote server's SSL certificate has already expired.",
                                    "cvss": "5.0 Medium CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N",
                                    "solution": "Purchase or generate a new SSL certificate to replace the existing one.",
                                    "risk": "SSL Certificate Expiry",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 932,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The remote service encrypts traffic using TLS / SSL but allows a client to insecurely renegotiate the connection after the initial handshake.\nAn unauthenticated, remote attacker may be able to leverage this issue to inject an arbitrary amount of plaintext into the beginning of the application protocol stream, which could facilitate man-in-the-middle attacks if the service assumes that the sessions before and after renegotiation are from the same 'client' and merges them at the application layer. The remote service allows insecure renegotiation of TLS / SSL connections.",
                                    "cvss": "5.8 Medium CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P",
                                    "solution": "Contact the vendor for specific patch information.",
                                    "risk": "SSL / TLS Renegotiation Handshakes MiTM Plaintext Data Injection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.ietf.org/mail-archive/web/tls/current/msg03948.html",
                                        "http://www.g-sec.lu/practicaltls.pdf",
                                        "https://tools.ietf.org/html/rfc5746"
                                    ]
                                }
                            ],
                            "Memory Corruption": [
                                {
                                    "id": 914,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "Server Temporary Key Size: 1024 bits\n\n",
                                    "cvss": "4.0 Medium AV:N/AC:H/Au:N/C:P/I:P/A:N",
                                    "solution": "Deploy (Ephemeral) Elliptic-Curve Diffie-Hellman (ECDHE) or use\n  a 2048-bit or stronger Diffie-Hellman group (see the references).\n\n  For Apache Web Servers:\n  Beginning with version 2.4.7, mod_ssl will use DH parameters which include primes with lengths of more than 1024 bits.",
                                    "risk": "SSL/TLS: Diffie-Hellman Key Exchange Insufficient DH Group Strength Vulnerability",
                                    "type": "Memory Corruption",
                                    "id_cve": [],
                                    "refs": [
                                        "https://weakdh.org/"
                                    ]
                                }
                            ],
                            "Gain Privileges": [
                                {
                                    "id": 922,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The remote host supports the use of SSL ciphers that offer medium strength encryption. Nessus regards medium strength as any encryption that uses key lengths at least 64 bits and less than 112 bits, or else that uses the 3DES encryption suite.\n\nNote that it is considerably easier to circumvent medium strength encryption if the attacker is on the same physical network. The remote service supports the use of medium strength SSL ciphers.",
                                    "cvss": "5.0 Medium CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N",
                                    "solution": "Reconfigure the affected application if possible to avoid use of medium strength ciphers.",
                                    "risk": "SSL Medium Strength Cipher Suites Supported (SWEET32)",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.openssl.org/blog/blog/2016/08/24/sweet32/",
                                        "https://sweet32.info"
                                    ]
                                },
                                {
                                    "id": 927,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The server's X.509 certificate cannot be trusted. This situation can occur in three different ways, in which the chain of trust can be broken, as stated below :\n\n  - First, the top of the certificate chain sent by the     server might not be descended from a known public     certificate authority. This can occur either when the     top of the chain is an unrecognized, self-signed     certificate, or when intermediate certificates are     missing that would connect the top of the certificate     chain to a known public certificate authority.\n\n  - Second, the certificate chain may contain a certificate     that is not valid at the time of the scan. This can     occur either when the scan occurs before one of the     certificate's 'notBefore' dates, or after one of the     certificate's 'notAfter' dates.\n\n  - Third, the certificate chain may contain a signature     that either didn't match the certificate's information     or could not be verified. Bad signatures can be fixed by     getting the certificate with the bad signature to be     re-signed by its issuer. Signatures that could not be     verified are the result of the certificate's issuer     using a signing algorithm that Nessus either does not     support or does not recognize.\n\nIf the remote host is a public host in production, any break in the chain makes it more difficult for users to verify the authenticity and identity of the web server. This could make it easier to carry out man-in-the-middle attacks against the remote host. The SSL certificate for this service cannot be trusted.",
                                    "cvss": "6.4 Medium CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N",
                                    "solution": "Purchase or generate a proper SSL certificate for this service.",
                                    "risk": "SSL Certificate Cannot Be Trusted",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.itu.int/rec/T-REC-X.509/en",
                                        "https://en.wikipedia.org/wiki/X.509"
                                    ]
                                }
                            ],
                            "Denial of Service (DoS)": [
                                {
                                    "id": 925,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The 'commonName' (CN) attribute of the SSL certificate presented for this service is for a different machine. The SSL certificate for this service is for a different host.",
                                    "cvss": "5.0 Medium CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N",
                                    "solution": "Purchase or generate a proper SSL certificate for this service.",
                                    "risk": "SSL Certificate with Wrong Hostname",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        },
                        "low": {
                            "Information Disclosure": [
                                {
                                    "id": 907,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other products, uses nondeterministic CBC padding, which makes it easier for man-in-the-middle attackers to obtain cleartext data via a padding-oracle attack, aka the \"POODLE\" issue.\n\nOpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly restrict processing of ChangeCipherSpec messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive information, via a crafted TLS handshake, aka the \"CCS Injection\" vulnerability.\n\n",
                                    "cvss": "7.4 High CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                    "solution": "Updates are available. Please see the references for more information.",
                                    "risk": "SSL/TLS: OpenSSL CCS Man in the Middle Security Bypass Vulnerability",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2014-0224",
                                        "CVE-2014-3566"
                                    ],
                                    "refs": [],
                                    "exploits": [
                                        null
                                    ],
                                    "patches": [],
                                    "mitigations": []
                                },
                                {
                                    "id": 909,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The remote SSL/TLS server is using the following certificate(s) with a RSA key with less than 2048 bits (public-key-size:public-key-algorithm:serial:issuer):\n\n1024:RSA:00FAF93A4C7FB6B9CC:1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX (Server certificate)\n",
                                    "cvss": "5.3 Medium CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "solution": "Replace the certificate with a stronger key and reissue the\n  certificates it signed.",
                                    "risk": "SSL/TLS: Server Certificate / Certificate in Chain with RSA keys less than 2048 bits",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.cabforum.org/wp-content/uploads/Baseline_Requirements_V1.pdf"
                                    ]
                                },
                                {
                                    "id": 908,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and other products, requires a server to send a ServerVerify message before establishing that a client possesses certain plaintext RSA data, which makes it easier for remote attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding oracle, aka a \"DROWN\" attack.\n\nIn addition to TLSv1.0+ the service is also providing the deprecated SSLv3 protocol and supports one or more ciphers. Those supported ciphers can be found in the 'SSL/TLS: Report Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.802067) VT.\n",
                                    "cvss": "5.9 Medium CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "solution": "It is recommended to disable the deprecated SSLv2 and/or SSLv3\n  protocols in favor of the TLSv1.2+ protocols. Please see the references for more information.",
                                    "risk": "SSL/TLS: Deprecated SSLv2 and SSLv3 Protocol Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [
                                        "CVE-2016-0800"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ]
                        },
                        "info": {
                            "Information Disclosure": [
                                {
                                    "id": 917,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The remote service accepts connections encrypted using SSL 2.0 and/or SSL 3.0. These versions of SSL are affected by several cryptographic flaws, including:\n\n  - An insecure padding scheme with CBC ciphers.\n\n  - Insecure session renegotiation and resumption schemes.\n\nAn attacker can exploit these flaws to conduct man-in-the-middle attacks or to decrypt communications between the affected service and clients.\n\nAlthough SSL/TLS has a secure means for choosing the highest supported version of the protocol (so that these versions will be used only if the client or server support nothing better), many web browsers implement this in an unsafe way that allows an attacker to downgrade a connection (such as in POODLE). Therefore, it is recommended that these protocols be disabled entirely.\n\nNIST has determined that SSL 3.0 is no longer acceptable for secure communications. As of the date of enforcement found in PCI DSS v3.1, any version of SSL will not meet the PCI SSC's definition of 'strong cryptography'. The remote service encrypts traffic using a protocol with known weaknesses.",
                                    "cvss": "10.0 High CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Consult the application's documentation to disable SSL 2.0 and 3.0.\nUse TLS 1.2 (with approved cipher suites) or higher instead.",
                                    "risk": "SSL Version 2 and 3 Protocol Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.schneier.com/academic/paperfiles/paper-ssl.pdf",
                                        "http://www.nessus.org/u?b06c7e95",
                                        "http://www.nessus.org/u?247c4540",
                                        "https://www.openssl.org/~bodo/ssl-poodle.pdf",
                                        "http://www.nessus.org/u?5d15ba70",
                                        "https://www.imperialviolet.org/2014/10/14/poodle.html",
                                        "https://tools.ietf.org/html/rfc7507",
                                        "https://tools.ietf.org/html/rfc7568"
                                    ]
                                }
                            ],
                            "Gain Privileges": [
                                {
                                    "id": 930,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The remote x509 certificate on the remote SSL server has been generated on a Debian or Ubuntu system which contains a bug in the random number generator of its OpenSSL library. \n\nThe problem is due to a Debian packager removing nearly all sources of entropy in the remote version of OpenSSL. \n\nAn attacker can easily obtain the private part of the remote key and use this to decipher the remote session or set up a man in the middle attack. The remote SSL certificate uses a weak key.",
                                    "cvss": "10.0 High CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Consider all cryptographic material generated on the remote host to be guessable.  In particuliar, all SSH, SSL and OpenVPN key material should be re-generated.",
                                    "risk": "Debian OpenSSH/OpenSSL Package Random Number Generator Weakness (SSL check)",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.nessus.org/u?107f9bdc",
                                        "http://www.nessus.org/u?f14f4224"
                                    ]
                                }
                            ]
                        },
                        "unknown": {
                            "Information Disclosure": [
                                {
                                    "id": 936,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "This plugin is a SYN 'half-open' port scanner.  It shall be reasonably quick even against a firewalled target. \n\nNote that SYN scans are less intrusive than TCP (full connect) scans against broken services, but they might cause problems for less robust firewalls and also leave unclosed connections on the remote target, if the network is loaded. It is possible to determine which TCP ports are open.",
                                    "cvss": "unknown",
                                    "solution": "Protect your target with an IP filter.",
                                    "risk": "Nessus SYN scanner",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 916,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The remote host supports the use of SSL ciphers that operate in Cipher Block Chaining (CBC) mode.  These cipher suites offer additional security over Electronic Codebook (ECB) mode, but have the potential to leak information if used improperly. The remote service supports the use of SSL Cipher Block Chaining ciphers, which combine previous blocks with subsequent ones.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSL Cipher Block Chaining Cipher Suites Supported",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.openssl.org/docs/manmaster/man1/ciphers.html",
                                        "http://www.nessus.org/u?cc4a822a",
                                        "https://www.openssl.org/~bodo/tls-cbc.txt"
                                    ]
                                },
                                {
                                    "id": 921,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The remote host supports the use of SSL ciphers that offer Perfect Forward Secrecy (PFS) encryption.  These cipher suites ensure that recorded SSL traffic cannot be broken at a future date if the server's private key is compromised. The remote service supports the use of SSL Perfect Forward Secrecy ciphers, which maintain confidentiality even if the key is stolen.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSL Perfect Forward Secrecy Cipher Suites Supported",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.openssl.org/docs/manmaster/man1/ciphers.html",
                                        "https://en.wikipedia.org/wiki/Diffie-Hellman_key_exchange",
                                        "https://en.wikipedia.org/wiki/Perfect_forward_secrecy"
                                    ]
                                },
                                {
                                    "id": 931,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "This plugin connects to every SSL-related port and attempts to extract and dump the X.509 certificate. This plugin displays the SSL certificate.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSL Certificate Information",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 934,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The remote PostgreSQL server supports the use of encryption initiated during pre-login to switch from a cleartext to an encrypted communications channel. The remote service supports encrypting traffic.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "PostgreSQL STARTTLS Support",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.postgresql.org/docs/9.2/protocol-flow.html#AEN96066",
                                        "https://www.postgresql.org/docs/9.2/protocol-message-formats.html"
                                    ]
                                },
                                {
                                    "id": 935,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The remote service is a PostgreSQL database server, or a derivative such as EnterpriseDB. A database service is listening on the remote host.",
                                    "cvss": "unknown",
                                    "solution": "Limit incoming traffic to this port if desired.",
                                    "risk": "PostgreSQL Server Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.postgresql.org/"
                                    ]
                                }
                            ],
                            "Gain Privileges": [
                                {
                                    "id": 905,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "Transport Layer Security (TLS) services that use Diffie-Hellman groups\nof insufficient strength, especially those using one of a few commonly\nshared groups, may be susceptible to passive eavesdropping attacks.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "ssl-dh-params",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "https://weakdh.org"
                                    ]
                                }
                            ],
                            "Denial of Service (DoS)": [
                                {
                                    "id": 919,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The remote host has open SSL/TLS ports which advertise discouraged cipher suites. It is recommended to only enable support for the following cipher suites:\n\nTLSv1.3:\n  - 0x13,0x01 TLS_AES_128_GCM_SHA256\n  - 0x13,0x02 TLS_AES_256_GCM_SHA384\n  - 0x13,0x03 TLS_CHACHA20_POLY1305_SHA256\n\nTLSv1.2:\n  - 0xC0,0x2B ECDHE-ECDSA-AES128-GCM-SHA256\n  - 0xC0,0x2F ECDHE-RSA-AES128-GCM-SHA256\n  - 0xC0,0x2C ECDHE-ECDSA-AES256-GCM-SHA384\n  - 0xC0,0x30 ECDHE-RSA-AES256-GCM-SHA384\n  - 0xCC,0xA9 ECDHE-ECDSA-CHACHA20-POLY1305\n  - 0xCC,0xA8 ECDHE-RSA-CHACHA20-POLY1305\n  - 0x00,0x9E DHE-RSA-AES128-GCM-SHA256\n  - 0x00,0x9F DHE-RSA-AES256-GCM-SHA384\n\nThis is the recommended configuration for the vast majority of services, as it is highly secure and compatible with nearly every client released in the last five (or more) years. The remote host advertises discouraged SSL/TLS ciphers.",
                                    "cvss": "unknown",
                                    "solution": "Only enable support for recommened cipher suites.",
                                    "risk": "SSL/TLS Recommended Cipher Suites",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "https://wiki.mozilla.org/Security/Server_Side_TLS",
                                        "https://ssl-config.mozilla.org/"
                                    ]
                                },
                                {
                                    "id": 924,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "This plugin detects which SSL ciphers are supported by the remote service for encrypting communications. The remote service encrypts communications using SSL.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSL Cipher Suites Supported",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.openssl.org/docs/man1.0.2/man1/ciphers.html",
                                        "http://www.nessus.org/u?e17ffced"
                                    ]
                                },
                                {
                                    "id": 926,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "The service running on the remote host presents an SSL certificate for which the 'commonName' (CN) attribute does not match the hostname on which the service listens. The 'commonName' (CN) attribute in the SSL certificate does not match the hostname.",
                                    "cvss": "unknown",
                                    "solution": "If the machine has several names, make sure that users connect to the service through the DNS hostname that matches the common name in the certificate.",
                                    "risk": "SSL Certificate 'commonName' Mismatch",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 933,
                                    "host": "192.168.81.131",
                                    "service": "5432/postgresql",
                                    "description": "This plugin detects which SSL and TLS versions are supported by the remote service for encrypting communications. The remote service encrypts communications.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "SSL / TLS Versions Supported",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        }
                    },
                    "8009/ajp13": {
                        "unknown": {
                            "File Inclusion": [
                                {
                                    "id": 937,
                                    "host": "192.168.81.131",
                                    "service": "8009/ajp13",
                                    "description": "unknown",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "unknown",
                                    "type": "File Inclusion",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        }
                    },
                    "8180/http": {
                        "unknown": {
                            "Denial of Service (DoS)": [
                                {
                                    "id": 938,
                                    "host": "192.168.81.131",
                                    "service": "8180/http",
                                    "description": "Apache HTTP Server is vulnerable to a denial of service. By sending specially-crafted partial HTTP requests, a remote attacker could exploit this vulnerability to cause a daemon outage.\n\nThe Apache HTTP Server 1.x and 2.x allows remote attackers to cause a denial of service (daemon outage) via partial HTTP requests, as demonstrated by Slowloris, related to the lack of the mod_reqtimeout module in versions before 2.2.15.\n\nSlowloris tries to keep many connections to the target web server open and hold\nthem open as long as possible.  It accomplishes this by opening connections to\nthe target web server and sending a partial request. By doing so, it starves\nthe http server's resources causing Denial Of Service.\n",
                                    "cvss": "unknown",
                                    "solution": "Apply the appropriate update for your system. See References.. Maggiori info (https://exchange.xforce.ibmcloud.com/vulnerabilities/72345)\n\nn/a",
                                    "risk": "http-stored-xss",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750",
                                        "http://ha.ckers.org/slowloris/"
                                    ],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ]
                        }
                    },
                    "general/tcp": {
                        "critical": {
                            "Information Disclosure": [
                                {
                                    "id": 941,
                                    "host": "192.168.81.131",
                                    "service": "general/tcp",
                                    "description": "The \"Ubuntu\" Operating System on the remote host has reached the end of life.\n\nCPE:               cpe:/o:canonical:ubuntu_linux:8.04\nInstalled version,\nbuild or SP:       8.04\nEOL date:          2013-05-09\nEOL info:          https://wiki.ubuntu.com/Releases\n",
                                    "cvss": "10.0 High AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Upgrade the OS on the remote host to a version which is still\n  supported and receiving security updates by the vendor.",
                                    "risk": "Operating System (OS) End of Life (EOL) Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        },
                        "low": {
                            "Information Disclosure": [
                                {
                                    "id": 942,
                                    "host": "192.168.81.131",
                                    "service": "general/tcp",
                                    "description": "It was detected that the host implements RFC1323/RFC7323.\n\nThe following timestamps were retrieved with a delay of 1 seconds in-between:\nPacket 1: 712328\nPacket 2: 712434\n",
                                    "cvss": "2.6 Low AV:N/AC:H/Au:N/C:P/I:N/A:N",
                                    "solution": "To disable TCP timestamps on linux add the line 'net.ipv4.tcp_timestamps = 0' to\n  /etc/sysctl.conf. Execute 'sysctl -p' to apply the settings at runtime.\n\n  To disable TCP timestamps on Windows execute 'netsh int tcp set global timestamps=disabled'\n\n  Starting with Windows Server 2008 and Vista, the timestamp can not be completely disabled.\n\n  The default behavior of the TCP/IP stack on this Systems is to not use the\n  Timestamp options when initiating TCP connections, but use them if the TCP peer\n  that is initiating communication includes them in their synchronize (SYN) segment.\n\n  See the references for more information.",
                                    "risk": "TCP timestamps",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.ietf.org/rfc/rfc1323.txt"
                                    ]
                                }
                            ]
                        },
                        "info": {
                            "Information Disclosure": [
                                {
                                    "id": 941,
                                    "host": "192.168.81.131",
                                    "service": "general/tcp",
                                    "description": "The \"Ubuntu\" Operating System on the remote host has reached the end of life.\n\nCPE:               cpe:/o:canonical:ubuntu_linux:8.04\nInstalled version,\nbuild or SP:       8.04\nEOL date:          2013-05-09\nEOL info:          https://wiki.ubuntu.com/Releases\n",
                                    "cvss": "10.0 High AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Upgrade the OS on the remote host to a version which is still\n  supported and receiving security updates by the vendor.",
                                    "risk": "Operating System (OS) End of Life (EOL) Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        }
                    },
                    "8009/nvme-disc": {
                        "critical": {
                            "Cross Site Request Forgery (CSRF)": [
                                {
                                    "id": 944,
                                    "host": "192.168.81.131",
                                    "service": "8009/nvme-disc",
                                    "description": "When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.\n\nIt was possible to read the file \"/WEB-INF/web.xml\" through the AJP connector.\n\nResult:\n\nAB 8\\x0004 Ã\\x0088 \\x0002OK  \\x0001 \\x000CContent-Type  \\x001Ctext/html;charset=ISO-8859-1 AB\\x001FÃ¼\\x0003\\x001FÃ¸<!--\n  Licensed to the Apache Software Foundation (ASF) under one or more\n  contributor license agreements.  See the NOTICE file distributed with\n  this work for additional information regarding copyright ownership.\n  The ASF licenses this file to You under the Apache License, Version 2.0\n  (the \"License\"); you may not use this file except in compliance with\n  the License.  You may obtain a copy of the License at\n\n      http://www.apache.org/licenses/LICENSE-2.0\n\n  Unless required by applicable law or agreed to in writing, software\n  distributed under the License is distributed on an \"AS IS\" BASIS,\n  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n  See the License for the specific language governing permissions and\n  limitations under the License.\n-->\n<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\"\n   \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n\n<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n    <head>\n    <title>Apache Tomcat/5.5</title>\n    <style type=\"text/css\">\n    /*<![CDATA[*/\n      body {\n          color: #000000;\n          background-color: #FFFFFF;\n\t  font-family: Arial, \"Times New Roman\", Times, serif;\n          margin: 10px 0px;\n      }\n\n    img {\n       border: none;\n    }\n    \n    a:link, a:visited {\n        color: blue\n    }\n\n    th {\n        font-family: Verdana, \"Times New Roman\", Times, serif;\n        font-size: 110%;\n        font-weight: normal;\n        font-style: italic;\n        background: #D2A41C;\n        text-align: left;\n    }\n\n    td {\n        color: #000000;\n\tfont-family: Arial, Helvetica, sans-serif;\n    }\n    \n    td.menu {\n        background: #FFDC75;\n    }\n\n    .center {\n        text-align: center;\n    }\n\n    .code {\n        color: #000000;\n        font-family: \"Courier New\", Courier, monospace;\n        font-size: 110%;\n        margin-left: 2.5em;\n    }\n    \n     #banner {\n        margin-bottom: 12px;\n     }\n\n     p#congrats {\n         margin-top: 0;\n         font-weight: bold;\n         text-align: center;\n     }\n\n     p#footer {\n         text-align: right;\n         font-size: 80%;\n     }\n     /*]]>*/\n   </style>\n</head>\n\n<body>\n\n<!-- Header -->\n<table id=\"banner\" width=\"100%\">\n    <tr>\n      <td align=\"left\" style=\"width:130px\">\n        <a href=\"http://tomcat.apache.org/\">\n\t  <img src=\"tomcat.gif\" height=\"92\" width=\"130\" alt=\"The Mighty Tomcat - MEOW!\"/>\n\t</a>\n      </td>\n      <td align=\"left\" valign=\"top\"><b>Apache Tomcat/5.5</b></td>\n      <td align=\"right\">\n        <a href=\"http://www.apache.org/\">\n\t  <img src=\"asf-logo-wide.gif\" height=\"51\" width=\"537\" alt=\"The Apache Software Foundation\"/>\n\t</a>\n       </td>\n     </tr>\n</table>\n\n<table>\n    <tr>\n\n        <!-- Table of Contents -->\n        <td valign=\"top\">\n            <table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"3\">\n                <tr>\n\t\t  <th>Administration</th>\n                </tr>\n                <tr>\n\t\t  <td class=\"menu\">\n\t\t    <a href=\"manager/status\">Status</a><br/>\n                    <a href=\"admin\">Tomcat&nbsp;Administration</a><br/>\n                    <a href=\"manager/html\">Tomcat&nbsp;Manager</a><br/>\n                    &nbsp;\n                  </td>\n                </tr>\n            </table>\n\n\t    <br />\n            <table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"3\">\n                <tr>\n\t\t  <th>Documentation</th>\n                </tr>\n                <tr>\n                  <td class=\"menu\">\n                    <a href=\"RELEASE-NOTES.txt\">Release&nbsp;Notes</a><br/>\n                    <a href=\"tomcat-docs/changelog.html\">Change&nbsp;Log</a><br/>\n                    <a href=\"tomcat-docs\">Tomcat&nbsp;Documentation</a><br/>                        &nbsp;\n                    &nbsp;\n\t\t    </td>\n                </tr>\n            </table>\n\t    \n            <br/>\n            <table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"3\">\n                <tr>\n                  <th>Tomcat Online</th>\n                </tr>\n                <tr>\n                  <td class=\"menu\">\n                    <a href=\"http://tomcat.apache.org/\">Home&nbsp;Page</a><br/>\n\t\t    <a href=\"http://tomcat.apache.org/faq/\">FAQ</a><br/>\n                    <a href=\"http://tomcat.apache.org/bugreport.html\">Bug&nbsp;Database</a><br/>\n                    <a href=\"http://issues.apache.org/bugzilla/buglist.cgi?bug_status=UNCONFIRMED&amp;bug_status=NEW&amp;bug_status=ASSIGNED&amp;bug_status=REOPENED&amp;bug_status=RESOLVED&amp;resolution=LATER&amp;resolution=REMIND&amp;resolution=---&amp;bugidtype=include&amp;product=Tomcat+5&amp;cmdtype=doit&amp;order=Importance\">Open Bugs</a><br/>\n                    <a href=\"http://mail-archives.apache.org/mod_mbox/tomcat-users/\">Users&nbsp;Mailing&nbsp;List</a><br/>\n                    <a href=\"http://mail-archives.apache.org/mod_mbox/tomcat-dev/\">Developers&nbsp;Mailing&nbsp;List</a><br/>\n                    <a href=\"irc://irc.freenode.net/#tomcat\">IRC</a><br/>\n\t\t    &nbsp;\n                  </td>\n                </tr>\n            </table>\n\t    \n            <br/>\n            <table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"3\">\n                <tr>\n                  <th>Examples</th>\n                </tr>\n                <tr>\n                  <td class=\"menu\">\n                    <a href=\"jsp-examples/\">JSP&nbsp;Examples</a><br/>\n                    <a href=\"servlets-examples/\">Servlet&nbsp;Examples</a><br/>\n                    <a href=\"webdav/\">WebDAV&nbsp;capabilities</a><br/>\n     \t\t    &nbsp;\n                  </td>\n                </tr>\n            </table>\n\t    \n            <br/>\n            <table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"3\">\n                <tr>\n\t\t  <th>Miscellaneous</th>\n                </tr>\n                <tr>\n                  <td class=\"menu\">\n                    <a href=\"http://java.sun.com/products/jsp\">Sun's&nbsp;Java&nbsp;Server&nbsp;Pages&nbsp;Site</a><br/>\n                    <a href=\"http://java.sun.com/products/servlet\">Sun's&nbsp;Servlet&nbsp;Site</a><br/>\n    \t\t    &nbsp;\n                  </td>\n                </tr>\n            </table>\n        </td>\n\n        <td style=\"width:20px\">&nbsp;</td>\n\t\n        <!-- Body -->\n        <td align=\"left\" valign=\"top\">\n          <p id=\"congrats\">If you're seeing this page via a web browser, it means you've setup Tomcat successfully. Congratulations!</p>\n \n          <p>As you may have guessed by now, this is the default Tomcat home page. It can be found on the local filesystem at:</p>\n          <p class=\"code\">$CATALINA_HOME/webapps/ROOT/index.jsp</p>\n\t  \n          <p>where \"$CATALINA_HOME\" is the root of the Tomcat installation directory. If you're seeing this page, and you don't think you should be, then either you're either a user who has arrived at new installation of Tomcat, or you're an administrator who hasn't got his/her setup quite right. Providing the latter is the case, please refer to the <a href=\"tomcat-docs\">Tomcat Documentation</a> for more detailed setup and administration information than is found in the INSTALL file.</p>\n\n            <p><b>NOTE:</b> This page is precompiled. If you change it, this page will not change since\n                  it was compiled into a servlet at build time.\n                  (See <tt>$CATALINA_HOME/webapps/ROOT/WEB-INF/web.xml</tt> as to how it was mapped.)\n            </p>\n\n            <p><b>NOTE: For security reasons, using the administration webapp\n            is restricted to users with role \"admin\". The manager webapp\n            is restricted to users with role \"manager\".</b>\n            Users are defined in <code>$CATALINA_HOME/conf/tomcat-users.xml</code>.</p>\n\n            <p>Included with this release are a host of sample Servlets and JSPs (with associated source code), extensive documentation (including the Servlet 2.4 and JSP 2.0 API JavaDoc), and an introductory guide to developing web applications.</p>\n\n            <p>Tomcat mailing lists are available at the Tomcat project web site:</p>\n\n           <ul>\n               <li><b><a href=\"mailto:users@tomcat.apache.org\">users@tomc\n",
                                    "cvss": "9.8 High CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "solution": "Update Apache Tomcat to version 7.0.100, 8.5.51, 9.0.31 or later. For other products\n  using Tomcat please contact the vendor for more information on fixed versions.",
                                    "risk": "Apache Tomcat AJP RCE Vulnerability (Ghostcat)",
                                    "type": "Cross Site Request Forgery (CSRF)",
                                    "id_cve": [
                                        "CVE-2020-1938"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ]
                        },
                        "high": {
                            "Execute arbitrary code on vulnerable system": [
                                {
                                    "id": 945,
                                    "host": "192.168.81.131",
                                    "service": "8009/nvme-disc",
                                    "description": "A file read/inclusion vulnerability was found in AJP connector. A  remote, unauthenticated attacker could exploit this vulnerability to read web application files from a vulnerable server. In instances where the vulnerable server allows file uploads, an attacker could upload malicious JavaServer Pages (JSP) code within a variety of file types and gain remote code execution (RCE). There is a vulnerable AJP connector listening on the remote host.",
                                    "cvss": "7.5 High CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                    "solution": "Update the AJP configuration to require authorization and/or upgrade the Tomcat server to 7.0.100, 8.5.51, 9.0.31 or later.",
                                    "risk": "Apache Tomcat AJP Connector Request Injection (Ghostcat)",
                                    "type": "Execute arbitrary code on vulnerable system",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.nessus.org/u?8ebe6246",
                                        "http://www.nessus.org/u?4e287adb",
                                        "http://www.nessus.org/u?cbc3d54e",
                                        "https://access.redhat.com/security/cve/CVE-2020-1745",
                                        "https://access.redhat.com/solutions/4851251",
                                        "http://www.nessus.org/u?dd218234",
                                        "http://www.nessus.org/u?dd772531",
                                        "http://www.nessus.org/u?2a01d6bf",
                                        "http://www.nessus.org/u?3b5af27e",
                                        "http://www.nessus.org/u?9dab109f",
                                        "http://www.nessus.org/u?5eafcf70"
                                    ]
                                }
                            ]
                        },
                        "low": {
                            "Cross Site Request Forgery (CSRF)": [
                                {
                                    "id": 944,
                                    "host": "192.168.81.131",
                                    "service": "8009/nvme-disc",
                                    "description": "When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.\n\nIt was possible to read the file \"/WEB-INF/web.xml\" through the AJP connector.\n\nResult:\n\nAB 8\\x0004 Ã\\x0088 \\x0002OK  \\x0001 \\x000CContent-Type  \\x001Ctext/html;charset=ISO-8859-1 AB\\x001FÃ¼\\x0003\\x001FÃ¸<!--\n  Licensed to the Apache Software Foundation (ASF) under one or more\n  contributor license agreements.  See the NOTICE file distributed with\n  this work for additional information regarding copyright ownership.\n  The ASF licenses this file to You under the Apache License, Version 2.0\n  (the \"License\"); you may not use this file except in compliance with\n  the License.  You may obtain a copy of the License at\n\n      http://www.apache.org/licenses/LICENSE-2.0\n\n  Unless required by applicable law or agreed to in writing, software\n  distributed under the License is distributed on an \"AS IS\" BASIS,\n  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n  See the License for the specific language governing permissions and\n  limitations under the License.\n-->\n<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\"\n   \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n\n<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n    <head>\n    <title>Apache Tomcat/5.5</title>\n    <style type=\"text/css\">\n    /*<![CDATA[*/\n      body {\n          color: #000000;\n          background-color: #FFFFFF;\n\t  font-family: Arial, \"Times New Roman\", Times, serif;\n          margin: 10px 0px;\n      }\n\n    img {\n       border: none;\n    }\n    \n    a:link, a:visited {\n        color: blue\n    }\n\n    th {\n        font-family: Verdana, \"Times New Roman\", Times, serif;\n        font-size: 110%;\n        font-weight: normal;\n        font-style: italic;\n        background: #D2A41C;\n        text-align: left;\n    }\n\n    td {\n        color: #000000;\n\tfont-family: Arial, Helvetica, sans-serif;\n    }\n    \n    td.menu {\n        background: #FFDC75;\n    }\n\n    .center {\n        text-align: center;\n    }\n\n    .code {\n        color: #000000;\n        font-family: \"Courier New\", Courier, monospace;\n        font-size: 110%;\n        margin-left: 2.5em;\n    }\n    \n     #banner {\n        margin-bottom: 12px;\n     }\n\n     p#congrats {\n         margin-top: 0;\n         font-weight: bold;\n         text-align: center;\n     }\n\n     p#footer {\n         text-align: right;\n         font-size: 80%;\n     }\n     /*]]>*/\n   </style>\n</head>\n\n<body>\n\n<!-- Header -->\n<table id=\"banner\" width=\"100%\">\n    <tr>\n      <td align=\"left\" style=\"width:130px\">\n        <a href=\"http://tomcat.apache.org/\">\n\t  <img src=\"tomcat.gif\" height=\"92\" width=\"130\" alt=\"The Mighty Tomcat - MEOW!\"/>\n\t</a>\n      </td>\n      <td align=\"left\" valign=\"top\"><b>Apache Tomcat/5.5</b></td>\n      <td align=\"right\">\n        <a href=\"http://www.apache.org/\">\n\t  <img src=\"asf-logo-wide.gif\" height=\"51\" width=\"537\" alt=\"The Apache Software Foundation\"/>\n\t</a>\n       </td>\n     </tr>\n</table>\n\n<table>\n    <tr>\n\n        <!-- Table of Contents -->\n        <td valign=\"top\">\n            <table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"3\">\n                <tr>\n\t\t  <th>Administration</th>\n                </tr>\n                <tr>\n\t\t  <td class=\"menu\">\n\t\t    <a href=\"manager/status\">Status</a><br/>\n                    <a href=\"admin\">Tomcat&nbsp;Administration</a><br/>\n                    <a href=\"manager/html\">Tomcat&nbsp;Manager</a><br/>\n                    &nbsp;\n                  </td>\n                </tr>\n            </table>\n\n\t    <br />\n            <table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"3\">\n                <tr>\n\t\t  <th>Documentation</th>\n                </tr>\n                <tr>\n                  <td class=\"menu\">\n                    <a href=\"RELEASE-NOTES.txt\">Release&nbsp;Notes</a><br/>\n                    <a href=\"tomcat-docs/changelog.html\">Change&nbsp;Log</a><br/>\n                    <a href=\"tomcat-docs\">Tomcat&nbsp;Documentation</a><br/>                        &nbsp;\n                    &nbsp;\n\t\t    </td>\n                </tr>\n            </table>\n\t    \n            <br/>\n            <table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"3\">\n                <tr>\n                  <th>Tomcat Online</th>\n                </tr>\n                <tr>\n                  <td class=\"menu\">\n                    <a href=\"http://tomcat.apache.org/\">Home&nbsp;Page</a><br/>\n\t\t    <a href=\"http://tomcat.apache.org/faq/\">FAQ</a><br/>\n                    <a href=\"http://tomcat.apache.org/bugreport.html\">Bug&nbsp;Database</a><br/>\n                    <a href=\"http://issues.apache.org/bugzilla/buglist.cgi?bug_status=UNCONFIRMED&amp;bug_status=NEW&amp;bug_status=ASSIGNED&amp;bug_status=REOPENED&amp;bug_status=RESOLVED&amp;resolution=LATER&amp;resolution=REMIND&amp;resolution=---&amp;bugidtype=include&amp;product=Tomcat+5&amp;cmdtype=doit&amp;order=Importance\">Open Bugs</a><br/>\n                    <a href=\"http://mail-archives.apache.org/mod_mbox/tomcat-users/\">Users&nbsp;Mailing&nbsp;List</a><br/>\n                    <a href=\"http://mail-archives.apache.org/mod_mbox/tomcat-dev/\">Developers&nbsp;Mailing&nbsp;List</a><br/>\n                    <a href=\"irc://irc.freenode.net/#tomcat\">IRC</a><br/>\n\t\t    &nbsp;\n                  </td>\n                </tr>\n            </table>\n\t    \n            <br/>\n            <table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"3\">\n                <tr>\n                  <th>Examples</th>\n                </tr>\n                <tr>\n                  <td class=\"menu\">\n                    <a href=\"jsp-examples/\">JSP&nbsp;Examples</a><br/>\n                    <a href=\"servlets-examples/\">Servlet&nbsp;Examples</a><br/>\n                    <a href=\"webdav/\">WebDAV&nbsp;capabilities</a><br/>\n     \t\t    &nbsp;\n                  </td>\n                </tr>\n            </table>\n\t    \n            <br/>\n            <table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"3\">\n                <tr>\n\t\t  <th>Miscellaneous</th>\n                </tr>\n                <tr>\n                  <td class=\"menu\">\n                    <a href=\"http://java.sun.com/products/jsp\">Sun's&nbsp;Java&nbsp;Server&nbsp;Pages&nbsp;Site</a><br/>\n                    <a href=\"http://java.sun.com/products/servlet\">Sun's&nbsp;Servlet&nbsp;Site</a><br/>\n    \t\t    &nbsp;\n                  </td>\n                </tr>\n            </table>\n        </td>\n\n        <td style=\"width:20px\">&nbsp;</td>\n\t\n        <!-- Body -->\n        <td align=\"left\" valign=\"top\">\n          <p id=\"congrats\">If you're seeing this page via a web browser, it means you've setup Tomcat successfully. Congratulations!</p>\n \n          <p>As you may have guessed by now, this is the default Tomcat home page. It can be found on the local filesystem at:</p>\n          <p class=\"code\">$CATALINA_HOME/webapps/ROOT/index.jsp</p>\n\t  \n          <p>where \"$CATALINA_HOME\" is the root of the Tomcat installation directory. If you're seeing this page, and you don't think you should be, then either you're either a user who has arrived at new installation of Tomcat, or you're an administrator who hasn't got his/her setup quite right. Providing the latter is the case, please refer to the <a href=\"tomcat-docs\">Tomcat Documentation</a> for more detailed setup and administration information than is found in the INSTALL file.</p>\n\n            <p><b>NOTE:</b> This page is precompiled. If you change it, this page will not change since\n                  it was compiled into a servlet at build time.\n                  (See <tt>$CATALINA_HOME/webapps/ROOT/WEB-INF/web.xml</tt> as to how it was mapped.)\n            </p>\n\n            <p><b>NOTE: For security reasons, using the administration webapp\n            is restricted to users with role \"admin\". The manager webapp\n            is restricted to users with role \"manager\".</b>\n            Users are defined in <code>$CATALINA_HOME/conf/tomcat-users.xml</code>.</p>\n\n            <p>Included with this release are a host of sample Servlets and JSPs (with associated source code), extensive documentation (including the Servlet 2.4 and JSP 2.0 API JavaDoc), and an introductory guide to developing web applications.</p>\n\n            <p>Tomcat mailing lists are available at the Tomcat project web site:</p>\n\n           <ul>\n               <li><b><a href=\"mailto:users@tomcat.apache.org\">users@tomc\n",
                                    "cvss": "9.8 High CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "solution": "Update Apache Tomcat to version 7.0.100, 8.5.51, 9.0.31 or later. For other products\n  using Tomcat please contact the vendor for more information on fixed versions.",
                                    "risk": "Apache Tomcat AJP RCE Vulnerability (Ghostcat)",
                                    "type": "Cross Site Request Forgery (CSRF)",
                                    "id_cve": [
                                        "CVE-2020-1938"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ]
                        },
                        "unknown": {
                            "Information Disclosure": [
                                {
                                    "id": 947,
                                    "host": "192.168.81.131",
                                    "service": "8009/nvme-disc",
                                    "description": "This plugin is a SYN 'half-open' port scanner.  It shall be reasonably quick even against a firewalled target. \n\nNote that SYN scans are less intrusive than TCP (full connect) scans against broken services, but they might cause problems for less robust firewalls and also leave unclosed connections on the remote target, if the network is loaded. It is possible to determine which TCP ports are open.",
                                    "cvss": "unknown",
                                    "solution": "Protect your target with an IP filter.",
                                    "risk": "Nessus SYN scanner",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Denial of Service (DoS)": [
                                {
                                    "id": 946,
                                    "host": "192.168.81.131",
                                    "service": "8009/nvme-disc",
                                    "description": "The remote host is running an AJP (Apache JServ Protocol) connector, a service by which a standalone web server such as Apache communicates over TCP with a Java servlet container such as Tomcat. There is an AJP connector listening on the remote host.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "AJP Connector Detection",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "http://tomcat.apache.org/connectors-doc/",
                                        "http://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html"
                                    ]
                                }
                            ]
                        }
                    },
                    "3632/distcc": {
                        "critical": {
                            "Gain Privileges": [
                                {
                                    "id": 949,
                                    "host": "192.168.81.131",
                                    "service": "3632/distcc",
                                    "description": "distcc 2.x, as used in XCode 1.5 and others, when not configured to restrict access to the server port, allows remote attackers to execute arbitrary commands via compilation jobs, which are executed by the server without authorization checks.\n\nIt was possible to execute the \"id\" command.\n\nResult: uid=1(daemon) gid=1(daemon)\n",
                                    "cvss": "9.3 High AV:N/AC:M/Au:N/C:C/I:C/A:C",
                                    "solution": "Vendor updates are available. Please see the references for\n  more information.\n\n  For more information about DistCC's security see the references.",
                                    "risk": "DistCC RCE Vulnerability (CVE-2004-2687)",
                                    "type": "Gain Privileges",
                                    "id_cve": [
                                        "CVE-2004-2687"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ]
                        },
                        "unknown": {
                            "Information Disclosure": [
                                {
                                    "id": 950,
                                    "host": "192.168.81.131",
                                    "service": "3632/distcc",
                                    "description": "This plugin is a SYN 'half-open' port scanner.  It shall be reasonably quick even against a firewalled target. \n\nNote that SYN scans are less intrusive than TCP (full connect) scans against broken services, but they might cause problems for less robust firewalls and also leave unclosed connections on the remote target, if the network is loaded. It is possible to determine which TCP ports are open.",
                                    "cvss": "unknown",
                                    "solution": "Protect your target with an IP filter.",
                                    "risk": "Nessus SYN scanner",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        }
                    },
                    "445/microsoft-ds": {
                        "medium": {
                            "Execute arbitrary code on vulnerable system": [
                                {
                                    "id": 952,
                                    "host": "192.168.81.131",
                                    "service": "445/microsoft-ds",
                                    "description": "The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the \"username map script\" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.\n\n",
                                    "cvss": "6.0 Medium AV:N/AC:M/Au:S/C:P/I:P/A:P",
                                    "solution": "Updates are available. Please see the referenced vendor advisory.",
                                    "risk": "Samba MS-RPC Remote Shell Command Execution Vulnerability - Active Check",
                                    "type": "Execute arbitrary code on vulnerable system",
                                    "id_cve": [
                                        "CVE-2007-2447"
                                    ],
                                    "refs": [],
                                    "exploits": [],
                                    "patches": [],
                                    "mitigations": []
                                }
                            ],
                            "Gain Privileges": [
                                {
                                    "id": 953,
                                    "host": "192.168.81.131",
                                    "service": "445/microsoft-ds",
                                    "description": "Signing is not required on the remote SMB server. An unauthenticated, remote attacker can exploit this to conduct man-in-the-middle attacks against the SMB server. Signing is not required on the remote SMB server.",
                                    "cvss": "5.0 Medium CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N",
                                    "solution": "Enforce message signing in the host's configuration. On Windows, this is found in the policy setting 'Microsoft network server: Digitally sign communications (always)'. On Samba, the setting is called 'server signing'. See the 'see also' links for further details.",
                                    "risk": "SMB Signing not required",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.nessus.org/u?df39b8b3",
                                        "http://technet.microsoft.com/en-us/library/cc731957.aspx",
                                        "http://www.nessus.org/u?74b80723",
                                        "https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html",
                                        "http://www.nessus.org/u?a3cac4ea"
                                    ]
                                }
                            ],
                            "Information Disclosure": [
                                {
                                    "id": 955,
                                    "host": "192.168.81.131",
                                    "service": "445/microsoft-ds",
                                    "description": "The version of Samba, a CIFS/SMB server for Linux and Unix, running on the remote host is affected by a flaw, known as Badlock, that exists in the Security Account Manager (SAM) and Local Security Authority (Domain Policy) (LSAD) protocols due to improper authentication level negotiation over Remote Procedure Call (RPC) channels. A man-in-the-middle attacker who is able to able to intercept the traffic between a client and a server hosting a SAM database can exploit this flaw to force a downgrade of the authentication level, which allows the execution of arbitrary Samba network calls in the context of the intercepted user, such as viewing or modifying sensitive security data in the Active Directory (AD) database or disabling critical services. An SMB server running on the remote host is affected by the Badlock vulnerability.",
                                    "cvss": "6.8 Medium CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P",
                                    "solution": "Upgrade to Samba version 4.2.11 / 4.3.8 / 4.4.2 or later.",
                                    "risk": "Samba Badlock Vulnerability",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "http://badlock.org",
                                        "https://www.samba.org/samba/security/CVE-2016-2118.html"
                                    ]
                                }
                            ]
                        },
                        "unknown": {
                            "Information Disclosure": [
                                {
                                    "id": 961,
                                    "host": "192.168.81.131",
                                    "service": "445/microsoft-ds",
                                    "description": "This plugin is a SYN 'half-open' port scanner.  It shall be reasonably quick even against a firewalled target. \n\nNote that SYN scans are less intrusive than TCP (full connect) scans against broken services, but they might cause problems for less robust firewalls and also leave unclosed connections on the remote target, if the network is loaded. It is possible to determine which TCP ports are open.",
                                    "cvss": "unknown",
                                    "solution": "Protect your target with an IP filter.",
                                    "risk": "Nessus SYN scanner",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 964,
                                    "host": "192.168.81.131",
                                    "service": "445/microsoft-ds",
                                    "description": "The remote service understands the CIFS (Common Internet File System) or Server Message Block (SMB) protocol, used to provide shared access to files, printers, etc between nodes on a network. A file / print sharing service is listening on the remote host.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Microsoft Windows SMB Service Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 954,
                                    "host": "192.168.81.131",
                                    "service": "445/microsoft-ds",
                                    "description": "Nessus was able to obtain the set of SMB2 and SMB3 dialects running on the remote host by sending an authentication request to port 139 or 445. It was possible to obtain information about the dialects of SMB2 and SMB3 available on the remote host.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Microsoft Windows SMB2 and SMB3 Dialects Supported (remote check)",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 957,
                                    "host": "192.168.81.131",
                                    "service": "445/microsoft-ds",
                                    "description": "Nessus was able to obtain the version of SMB running on the remote host by sending an authentication request to port 139 or 445.\n\nNote that this plugin is a remote check and does not work on agents. It was possible to obtain information about the version of SMB running on the remote host.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Microsoft Windows SMB Versions Supported (remote check)",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 958,
                                    "host": "192.168.81.131",
                                    "service": "445/microsoft-ds",
                                    "description": "It was possible to obtain the browse list of the remote Windows system by sending a request to the LANMAN pipe. The browse list is the list of the nearest Windows systems of the remote host. It is possible to obtain network information.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Microsoft Windows SMB LanMan Pipe Server Listing Disclosure",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 960,
                                    "host": "192.168.81.131",
                                    "service": "445/microsoft-ds",
                                    "description": "Nessus was able to obtain the samba version from the remote operating by sending an authentication request to port 139 or 445. Note that this plugin requires SMB1 to be enabled on the host. It was possible to obtain the samba version from the remote operating system.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Samba Version",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 962,
                                    "host": "192.168.81.131",
                                    "service": "445/microsoft-ds",
                                    "description": "Nessus was able to obtain the remote operating system name and version (Windows and/or Samba) by sending an authentication request to port 139 or 445. Note that this plugin requires SMB to be enabled on the host. It was possible to obtain information about the remote operating system.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Microsoft Windows SMB NativeLanManager Remote System Information Disclosure",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Denial of Service (DoS)": [
                                {
                                    "id": 956,
                                    "host": "192.168.81.131",
                                    "service": "445/microsoft-ds",
                                    "description": "The remote Windows host supports Server Message Block Protocol version 1 (SMBv1). Microsoft recommends that users discontinue the use of SMBv1 due to the lack of security features that were included in later SMB versions. Additionally, the Shadow Brokers group reportedly has an exploit that affects SMB; however, it is unknown if the exploit affects SMBv1 or another version. In response to this, US-CERT recommends that users disable SMBv1 per SMB best practices to mitigate these potential issues. The remote Windows host supports the SMBv1 protocol.",
                                    "cvss": "unknown",
                                    "solution": "Disable SMBv1 according to the vendor instructions in Microsoft KB2696547. Additionally, block SMB directly by blocking TCP port 445 on all network boundary devices. For SMB over the NetBIOS API, block TCP ports 137 / 139 and UDP ports 137 / 138 on all network boundary devices.",
                                    "risk": "Server Message Block (SMB) Protocol Version 1 Enabled (uncredentialed check)",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/",
                                        "https://support.microsoft.com/en-us/help/2696547/how-to-detect-enable-and-disable-smbv1-smbv2-and-smbv3-in-windows-and",
                                        "http://www.nessus.org/u?8dcab5e4",
                                        "http://www.nessus.org/u?234f8ef8",
                                        "http://www.nessus.org/u?4c7e0cf3"
                                    ]
                                },
                                {
                                    "id": 963,
                                    "host": "192.168.81.131",
                                    "service": "445/microsoft-ds",
                                    "description": "The remote host is running Samba, a CIFS/SMB server for Linux and Unix. An SMB server is running on the remote host.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Samba Server Detection",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": [
                                        "https://www.samba.org/"
                                    ]
                                }
                            ],
                            "Gain Privileges": [
                                {
                                    "id": 959,
                                    "host": "192.168.81.131",
                                    "service": "445/microsoft-ds",
                                    "description": "WMI (Windows Management Instrumentation) is not available on the remote host over DCOM. WMI queries are used to gather information about the remote host, such as its current state, network interface configuration, etc.\n\nWithout this information Nessus may not be able to identify installed software or security vunerabilities that exist on the remote host. WMI queries could not be made against the remote host.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "WMI Not Available",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page"
                                    ]
                                }
                            ]
                        }
                    },
                    "0/tcp": {
                        "critical": {
                            "Denial of Service (DoS)": [
                                {
                                    "id": 988,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "According to its self-reported version number, the Unix operating system running on the remote host is no longer supported.\n\nLack of support implies that no new security patches for the product will be released by the vendor. As a result, it is likely to contain security vulnerabilities. The operating system running on the remote host is no longer supported.",
                                    "cvss": "10.0 High CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Upgrade to a version of the Unix operating system that is currently supported.",
                                    "risk": "Unix Operating System Unsupported Version Detection",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        },
                        "info": {
                            "Denial of Service (DoS)": [
                                {
                                    "id": 988,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "According to its self-reported version number, the Unix operating system running on the remote host is no longer supported.\n\nLack of support implies that no new security patches for the product will be released by the vendor. As a result, it is likely to contain security vulnerabilities. The operating system running on the remote host is no longer supported.",
                                    "cvss": "10.0 High CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "solution": "Upgrade to a version of the Unix operating system that is currently supported.",
                                    "risk": "Unix Operating System Unsupported Version Detection",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "ICMP Timestamp Request Remote Date Disclosure": [
                                {
                                    "id": 996,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "The remote host answers to an ICMP timestamp request.  This allows an attacker to know the date that is set on the targeted machine, which may assist an unauthenticated, remote attacker in defeating time-based authentication protocols.\n\nTimestamps returned from machines running Windows Vista / 7 / 2008 / 2008 R2 are deliberately incorrect, but usually within 1000 seconds of the actual system time. It is possible to determine the exact time set on the remote host.",
                                    "cvss": "0.0 Low CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:N",
                                    "solution": "Filter out the ICMP timestamp requests (13), and the outgoing ICMP timestamp replies (14).",
                                    "risk": "ICMP Timestamp Request Remote Date Disclosure",
                                    "type": "ICMP Timestamp Request Remote Date Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        },
                        "unknown": {
                            "Information Disclosure": [
                                {
                                    "id": 981,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "This plugin displays, for each tested host, information about the scan itself :\n\n  - The version of the plugin set.\n  - The type of scanner (Nessus or Nessus Home).\n  - The version of the Nessus Engine.\n  - The port scanner(s) used.\n  - The port range scanned.\n  - The ping round trip time \n  - Whether credentialed or third-party patch management     checks are possible.\n  - Whether the display of superseded patches is enabled\n  - The date of the scan.\n  - The duration of the scan.\n  - The number of hosts scanned in parallel.\n  - The number of checks done in parallel. This plugin displays information about the Nessus scan.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Nessus Scan Information",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 983,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "By using information obtained from a Nessus scan, this plugin reports CPE (Common Platform Enumeration) matches for various hardware and software products found on a host. \n\nNote that if an official CPE is not available for the product, this plugin computes the best possible CPE based on the information available from the scan. It was possible to enumerate CPE names that matched on the remote system.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Common Platform Enumeration (CPE)",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "http://cpe.mitre.org/",
                                        "https://nvd.nist.gov/products/cpe"
                                    ]
                                },
                                {
                                    "id": 984,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "The remote host is missing one or more security patches. This plugin lists the newest version of each patch to install to make sure the remote host is up-to-date.\n\nNote: Because the 'Show missing patches that have been superseded' setting in your scan policy depends on this plugin, it will always run and cannot be disabled. The remote host is missing several patches.",
                                    "cvss": "unknown",
                                    "solution": "Install the patches listed below.",
                                    "risk": "Patch Report",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 994,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "Makes a traceroute to the remote host. It was possible to obtain traceroute information.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Traceroute Information",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Denial of Service (DoS)": [
                                {
                                    "id": 982,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "OS Security Patch Assessment is not available on the remote host.\nThis does not necessarily indicate a problem with the scan.\nCredentials may not have been provided, OS security patch assessment may not be supported for the target, the target may not have been identified, or another issue may have occurred that prevented OS security patch assessment from being available. See plugin output for details.\n\nThis plugin reports non-failure information impacting the availability of OS Security Patch Assessment. Failure information is reported by plugin 21745 : 'OS Security Patch Assessment failed'.  If a target host is not supported for OS Security Patch Assessment, plugin 110695 : 'OS Security Patch Assessment Checks Not Supported' will report concurrently with this plugin. OS Security Patch Assessment is not available.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "OS Security Patch Assessment Not Available",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 985,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "One of several ports that were previously open are now closed or unresponsive.\n\nThere are several possible reasons for this :\n\n  - The scan may have caused a service to freeze or stop     running.\n\n  - An administrator may have stopped a particular service     during the scanning process.\n\nThis might be an availability problem related to the following :\n\n  - A network outage has been experienced during the scan,     and the remote network cannot be reached anymore by the     scanner.\n\n  - This scanner may has been blacklisted by the system     administrator or by an automatic intrusion detection /     prevention system that detected the scan.\n\n  - The remote host is now down, either because a user     turned it off during the scan or because a select denial     of service was effective.\n\nIn any case, the audit of the remote host might be incomplete and may need to be done again. Previously open ports are now closed.",
                                    "cvss": "unknown",
                                    "solution": "- Increase checks_read_timeout and/or reduce max_checks.\n\n- Disable any IPS during the Nessus scan",
                                    "risk": "Open Port Re-check",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 986,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "Nessus was not able to successfully authenticate directly to the remote target on an available authentication protocol. Nessus was able to connect to the remote port and identify that the service running on the port supports an authentication protocol, but Nessus failed to authenticate to the remote service using the provided credentials. There may have been a protocol failure that prevented authentication from being attempted or all of the provided credentials for the authentication protocol may be invalid. See plugin output for error details.\n\nPlease note the following :\n\n- This plugin reports per protocol, so it is possible for   valid credentials to be provided for one protocol and not   another. For example, authentication may succeed via SSH   but fail via SMB, while no credentials were provided for   an available SNMP service.\n\n- Providing valid credentials for all available   authentication protocols may improve scan coverage, but   the value of successful authentication for a given   protocol may vary from target to target depending upon   what data (if any) is gathered from the target via that   protocol. For example, successful authentication via SSH   is more valuable for Linux targets than for Windows   targets, and likewise successful authentication via SMB   is more valuable for Windows targets than for Linux   targets. Nessus was able to find common ports used for local checks, however, no credentials were provided in the scan policy.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Target Credential Status by Authentication Protocol - No Credentials Provided",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 987,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "Based on the remote operating system, it is possible to determine what the remote system type is (eg: a printer, router, general-purpose computer, etc). It is possible to guess the remote device type.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Device Type",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 991,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "According to the MAC address of its network adapter, the remote host is a VMware virtual machine. The remote host is a VMware virtual machine.",
                                    "cvss": "unknown",
                                    "solution": "Since it is physically accessible through the network, ensure that its configuration matches your organization's security policy.",
                                    "risk": "VMware Virtual Machine Detection",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Gain Privileges": [
                                {
                                    "id": 989,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "Using a combination of remote probes (e.g., TCP/IP, SMB, HTTP, NTP, SNMP, etc.), it is possible to guess the name of the remote operating system in use. It is also possible sometimes to guess the version of the operating system. It is possible to guess the remote operating system.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "OS Identification",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 992,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "This plugin gathers MAC addresses discovered from both remote probing of the host (e.g. SNMP and Netbios) and from running local checks (e.g. ifconfig). It then consolidates the MAC addresses into a single, unique, and uniform list. This plugin gathers MAC addresses from various sources and consolidates them into a list.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Ethernet MAC Addresses",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 993,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "Nessus was able to extract the banner of the Apache web server and determine which Linux distribution the remote host is running. The name of the Linux distribution running on the remote host was found in the banner of the web server.",
                                    "cvss": "unknown",
                                    "solution": "If you do not wish to display this information, edit 'httpd.conf' and set the directive 'ServerTokens Prod' and restart Apache.",
                                    "risk": "Apache Banner Linux Distribution Disclosure",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 995,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "The remote host implements TCP timestamps, as defined by RFC1323.  A side effect of this feature is that the uptime of the remote host can sometimes be computed. The remote service implements TCP timestamps.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "TCP/IP Timestamps Supported",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.ietf.org/rfc/rfc1323.txt"
                                    ]
                                }
                            ],
                            "Memory Corruption": [
                                {
                                    "id": 990,
                                    "host": "192.168.81.131",
                                    "service": "0/tcp",
                                    "description": "Each ethernet MAC address starts with a 24-bit Organizationally Unique Identifier (OUI). These OUIs are registered by IEEE. The manufacturer can be identified from the Ethernet OUI.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Ethernet Card Manufacturer Detection",
                                    "type": "Memory Corruption",
                                    "id_cve": [],
                                    "refs": [
                                        "https://standards.ieee.org/faqs/regauth.html",
                                        "http://www.nessus.org/u?794673b4"
                                    ]
                                }
                            ]
                        }
                    },
                    "8180/tcp": {
                        "high": {
                            "Information Disclosure": [
                                {
                                    "id": 1006,
                                    "host": "192.168.81.131",
                                    "service": "8180/tcp",
                                    "description": "According to its version, the remote web server is obsolete and no longer maintained by its vendor or provider.\n\nLack of support implies that no new security patches for the product will be released by the vendor. As a result, it may contain security vulnerabilities. The remote web server is obsolete / unsupported.",
                                    "cvss": "7.5 High CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                    "solution": "Remove the web server if it is no longer needed. Otherwise, upgrade to a supported version if possible or switch to another server.",
                                    "risk": "Unsupported Web Server Detection",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        },
                        "medium": {
                            "Information Disclosure": [
                                {
                                    "id": 1008,
                                    "host": "192.168.81.131",
                                    "service": "8180/tcp",
                                    "description": "The default error page, default index page, example JSPs and/or example servlets are installed on the remote Apache Tomcat server. These files should be removed as they may help an attacker uncover information about the remote Tomcat install or host itself. The remote web server contains default files.",
                                    "cvss": "5.0 Medium CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N",
                                    "solution": "Delete the default index page and remove the example JSP and servlets. Follow the Tomcat or OWASP instructions to replace or modify the default error page.",
                                    "risk": "Apache Tomcat Default Files",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": [
                                        "http://www.nessus.org/u?4cb3b4dd",
                                        "https://www.owasp.org/index.php/Securing_tomcat"
                                    ]
                                }
                            ]
                        },
                        "unknown": {
                            "Denial of Service (DoS)": [
                                {
                                    "id": 1013,
                                    "host": "192.168.81.131",
                                    "service": "8180/tcp",
                                    "description": "Nessus was able to identify the remote service by its banner or by looking at the error message it sends when it receives an HTTP request. The remote service could be identified.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Service Detection",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 1007,
                                    "host": "192.168.81.131",
                                    "service": "8180/tcp",
                                    "description": "This test gives some information about the remote HTTP protocol - the version used, whether HTTP Keep-Alive and HTTP pipelining are enabled, etc... \n\nThis test is informational only and does not denote any security problem. Some information about the remote HTTP configuration can be extracted.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "HyperText Transfer Protocol (HTTP) Information",
                                    "type": "Denial of Service (DoS)",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Information Disclosure": [
                                {
                                    "id": 1014,
                                    "host": "192.168.81.131",
                                    "service": "8180/tcp",
                                    "description": "This plugin is a SYN 'half-open' port scanner.  It shall be reasonably quick even against a firewalled target. \n\nNote that SYN scans are less intrusive than TCP (full connect) scans against broken services, but they might cause problems for less robust firewalls and also leave unclosed connections on the remote target, if the network is loaded. It is possible to determine which TCP ports are open.",
                                    "cvss": "unknown",
                                    "solution": "Protect your target with an IP filter.",
                                    "risk": "Nessus SYN scanner",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 1010,
                                    "host": "192.168.81.131",
                                    "service": "8180/tcp",
                                    "description": "The 'favicon.ico' file found on the remote web server belongs to a popular web server. This may be used to fingerprint the web server. The remote web server contains a graphic image that is prone to information disclosure.",
                                    "cvss": "unknown",
                                    "solution": "Remove the 'favicon.ico' file or create a custom one for your site.",
                                    "risk": "Web Server / Application favicon.ico Vendor Fingerprinting",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                },
                                {
                                    "id": 1012,
                                    "host": "192.168.81.131",
                                    "service": "8180/tcp",
                                    "description": "The remote web server uses its default welcome page. Therefore, it's probable that this server is not used at all or is serving content that is meant to be hidden. The remote web server is not configured or is improperly configured.",
                                    "cvss": "unknown",
                                    "solution": "Disable this service if you do not use it.",
                                    "risk": "Web Server Unconfigured - Default Install Page Present",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Execute arbitrary code on vulnerable system": [
                                {
                                    "id": 1011,
                                    "host": "192.168.81.131",
                                    "service": "8180/tcp",
                                    "description": "This plugin attempts to determine the type and the version of the   remote web server. A web server is running on the remote host.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "HTTP Server Type and Version",
                                    "type": "Execute arbitrary code on vulnerable system",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ],
                            "Gain Privileges": [
                                {
                                    "id": 1009,
                                    "host": "192.168.81.131",
                                    "service": "8180/tcp",
                                    "description": "Nessus was able to detect a remote Apache Tomcat web server. The remote web server is an Apache Tomcat server.",
                                    "cvss": "unknown",
                                    "solution": "\n\nThe Apache Tomcat Project is proud to announce the release of version 10.1.1\nof Apache Tomcat. This release implements specifications that are part of the\nJakarta EE 10 platform.\nApplications that run on Tomcat 9 and earlier will not run on Tomcat 10\nwithout changes. Java EE based applications designed for Tomcat 9 and earlier\nmay be placed in the <code>$CATALINA_BASE/webapps-javaee</code> directory and\nTomcat will automatically convert them to Jakarta EE and copy them to the\nwebapps directory. This conversion is performed using the\n<a href=\"https://github.com/apache/tomcat-jakartaee-migration\">Apache Tomcat\nmigration tool for Jakarta EE tool</a> which is also available as a separate\n<a href=\"https://tomcat.apache.org/download-migration.cgi\">download</a> for off-line use.\nThe notable changes in this release are:\n\nFix bug <a href=\"https://bz.apache.org/bugzilla/show_bug.cgi?id=66277\">66277</a>, a refactoring regression that broke JSP includes\n    amongst other functionality\nFix unexpected timeouts that may appear as client disconnections when using\n    HTTP/2 and NIO2\nEnforce the requirement of RFC 7230 onwards that a request with a malformed\n    content-length header should always be rejected with a 400 response. \n\n\nFull details of these changes, and all the other changes, are available in the\n<a href=\"tomcat-10.1-doc/changelog.html#Tomcat_10.1.1_(markt)\">Tomcat 10.1\nchangelog</a>.\n\n\n\n<a href=\"https://tomcat.apache.org/download-10.cgi\">Download</a>\n\n",
                                    "risk": "Apache Tomcat Detection",
                                    "type": "Gain Privileges",
                                    "id_cve": [],
                                    "refs": [
                                        "https://tomcat.apache.org/"
                                    ]
                                }
                            ]
                        }
                    },
                    "137/netbios-ns": {
                        "unknown": {
                            "Information Disclosure": [
                                {
                                    "id": 1016,
                                    "host": "192.168.81.131",
                                    "service": "137/netbios-ns",
                                    "description": "The remote host is listening on UDP port 137 or TCP port 445, and replies to NetBIOS nbtscan or SMB requests.\n\nNote that this plugin gathers information to be used in other plugins, but does not itself generate a report. It was possible to obtain the network name of the remote host.",
                                    "cvss": "unknown",
                                    "solution": "n/a",
                                    "risk": "Windows NetBIOS / SMB Remote Host Information Disclosure",
                                    "type": "Information Disclosure",
                                    "id_cve": [],
                                    "refs": []
                                }
                            ]
                        }
                    }
                }
            }
        }

        this.hosts = Object.keys(this.final_summary.vulnerabilities)

        var x = []
    }

    ngOnInit(): void {
    }

    /*Invia i files XML caricati al server*/
    sendXMLs2Server(form: NgForm) {

        this.flag_vuln_button_clicked = true;

        console.log('flag Nessus', this.flag_nessus); console.log('flag Nmap', this.flag_nmap);
        console.log('flag OWASP ZAP', this.flag_owaspzap); console.log('flag OPEN VAS', this.flag_openvas);

        //Modo per caricare il body quando si utilizza un form con caricamento di files/BLOB
        let body = new FormData();

        let uploadNMAP = this.findByTool('Nmap'); //Restituisce il file relativo a NMAP (se esiste), altrimenti undefined
        let uploadNESSUS = this.findByTool('Nessus'); //Restituisce il file relativo a Nessus (se esiste), altrimenti undefined
        let uploadOPENVAS = this.findByTool('OpenVAS'); //Restituisce il file relativo a OpenVAS (se esiste), altrimenti undefined
        let uploadOWASPZAP = this.findByTool('OWASP ZAP'); //Restituisce il file relativo a OWASP ZAP (se esiste), altrimenti undefined

        console.log('uploadNMAP', uploadNMAP)
        console.log('uploadNessus', uploadNESSUS)
        console.log('uploadOPENVAS', uploadOPENVAS)
        console.log('uploadOWASPZAP', uploadOWASPZAP)

        //Inserisce nel body i flag dei vari files caricati (per ogni tool nmap, nessus, ecc... vede se effettivamente viene caricato un documento sul server) 
        body.set('flag_nmap', this.flag_nmap.toString())
        body.set('flag_nessus', this.flag_nessus.toString())
        body.set('flag_openvas', this.flag_openvas.toString())
        body.set('flag_owaspzap', this.flag_owaspzap.toString())

        //Inserisce nel body della richiesta i documenti caricati, etichettandoli in base al tool utilizzato (es: nmap, openvas, ecc..)
        if (uploadNMAP != undefined)
            body.set('nmap', uploadNMAP, 'nmap-' + uploadNMAP.name); //set body e aggiorna nome del file inserendo in testa il nome del tool utilizzato (es: file.xml -> nmap-file.xml)
        if (uploadNESSUS != undefined)
            body.set('nessus', uploadNESSUS, 'nessus-' + uploadNESSUS.name); //set body e aggiorna nome del file inserendo in testa il nome del tool utilizzato (es: file.xml -> nessus-file.xml)
        if (uploadOPENVAS != undefined)
            body.set('openvas', uploadOPENVAS, 'openvas-' + uploadOPENVAS.name); //set body e aggiorna nome del file inserendo in testa il nome del tool utilizzato (es: file.xml -> openvas-file.xml)
        if (uploadOWASPZAP != undefined)
            body.set('owaspzap', uploadOWASPZAP, 'owaspzap-' + uploadOWASPZAP.name); //set body e aggiorna nome del file inserendo in testa il nome del tool utilizzato (es: file.xml -> owaspzap-file.xml)

        //Header per il caricamento dei files
        let headers = new HttpHeaders();
        headers.set('Content-Type', 'multipart/form-data');

        this.http.post<any>(this.mainService.baseURL + '/loadXML/getXMLFiles/', body)
            .subscribe((response: any) => {

                this.status++; //prima fase completata
                this.value = 33; //aggiorna progress bar

                console.log('getXMLFILES response: ', response);
                this.merge_summary = response.x_summary
                this.dataFromMock = []

                for (var host in this.merge_summary.vulnerabilities) {
                    //console.log(' name=' + key + ' value=' + this.merge_summary.vulnerabilities[key]);
                    for (var service in this.merge_summary.vulnerabilities[host]) {
                        //console.log('service property name' + k)
                        //console.log('vulnerabilities 1', this.merge_summary.vulnerabilities[key][k])
                        for (var type in this.merge_summary.vulnerabilities[host][service]) {

                            this.merge_summary.vulnerabilities[host][service][type].forEach((vuln: any) => {
                                //console.log('vuln', vuln)  
                                this.dataFromMock.push(vuln)
                            })
                        }
                    }
                }

                //Seconda chiamata per la fase 2: Nightmare (Web Harvesting) per il data integration passando il filename del report ottenuto dalla chiamata getXMLFiles (fine step 1)
                let body = {
                    //ref : 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192',
                    x_summary_filename: response.x_summary_filename
                }

                this.http.post<any>(this.mainService.baseURL + '/webScraping/', body)
                    .subscribe((response: any) => {

                        this.status++; //seconda fase completata
                        this.value = 66; //aggiorna progress bar

                        console.log('webScraping response', response);

                        //Terza chiamata per la fase 3: il classificatore Bayesiano si occuperà di labellare le vulnerabilità in base al tipo e attribuirgli un livello di severity sulla base del CVSS3.0
                        let body = {
                            z_summary_filename: response.z_summary_filename
                        }

                        this.http.post<any>(this.mainService.baseURL + '/ai/', body)
                            .subscribe((response: any) => {
                                this.status++; //terza fase completata
                                this.value = 100; //aggiorna progress bar

                                console.log('bayesianClassifier response', response);
                                this.flag_show_report = true;
                                this.final_summary = response.final_summary
                                console.log('FINALLLL DA CAPIRE CGE CAAAA STAMPAAAAAA', this.final_summary)

                            }, error => {
                                console.log('bayesianClassifier error', error)
                                this.mainService.error_message = 'classificazione delle vulnerabilità tramite il modello Naive Bayes'
                                this.router.navigateByUrl('/error')
                            })

                    }, error => {
                        console.log('webScraping error', error)
                        this.mainService.error_message = 'Web Harvesting'
                        this.router.navigateByUrl('/error')
                    })

            }, error => {
                console.log('loadXML error', error)
                this.mainService.error_message = 'caricamento dei file XMLS relativi ai report. Riprova e sii sicuro di caricare i file relativi a ciascun tool tramite il pulsante dedicato'
                this.router.navigateByUrl('/error')
            })
    }

    simulateClick(tool: string) {
        console.log('click')
        let x = document.getElementById(tool);
        x?.click()
    }

    /*Funzione che viene richiamata ogni volta che un utente carica un file XML*/
    newXML($event: any, tool: string) {
        console.log('newXMLs tool', tool)

        console.log('load', $event)
        for (let i = 0; i < $event.target.files.length; i++) {
            let obj: FileXML = {
                name: $event.target.files[i].name,
                size: $event.target.files[i].size,
                type: $event.target.files[i].type,
                tool: tool,
                lastModified: $event.target.files[i].lastModifiedDate,
                file: $event.target.files[i],
            };
            if (!this.files.get(obj.name)) {  //se il file non è già stato caricato in precedenza lo carica altrimenti lo ignora
                this.files.set(obj.name, obj)
                this.setToolFlag(tool); //aggiorna il flag relativo allo strumento
            } else {
                alert('Il file è già stato caricato utilizzando un altro tool!')
            }

            this.setXMLsList();  //aggiorna la view con i file XML caricati

        }

        console.log("this.files", this.files)
    }

    /*Cancella il file con index = index*/
    removeFile(key: string, tool: string) {
        let files: FileXML[] = []
        console.log('file da cancellare: ', key);

        if (this.files.get(key)) {
            this.files.delete(key) //rimuove il file desiderato
            this.removeToolFlag(tool) //aggiorna il flag relativo al tool con cui è stato ottenuto l'XML
            this.setXMLsList() //aggiorna la view
        }

    }

    /*Copia il contenuto del Map nell'array xmls in modo da aggiornare la view*/
    setXMLsList() {
        this.xmls = []
        this.files.forEach((value: FileXML, key: string) => {
            this.xmls.push(value)
        });
        console.log('XMLs aggiornato: ', this.xmls)
    }

    /**Aggiorna il flag relativo al tool che è stato utilizzato per ottenere l'XML che viene caricato tramite form (documento aggiunto)*/
    setToolFlag(tool: string) {
        if (tool == 'Nmap')
            this.flag_nmap = true;
        if (tool == 'Nessus')
            this.flag_nessus = true;
        if (tool == 'OWASP ZAP')
            this.flag_owaspzap = true;
        if (tool == 'OpenVAS')
            this.flag_openvas = true;
    }

    /**Aggiorna il flag relativo al tool che è stato utilizzato per ottenere l'XML che viene caricato tramite form (documento rimosso)*/
    removeToolFlag(tool: string) {
        if (tool == 'Nmap')
            this.flag_nmap = false;
        if (tool == 'Nessus')
            this.flag_nessus = false;
        if (tool == 'OWASP ZAP')
            this.flag_owaspzap = false;
        if (tool == 'OpenVAS')
            this.flag_openvas = false;
    }

    /*Restituisce il file tra quelli caricati per mezzo di un particolare tool, restituisce undefined se il documento non esiste*/
    findByTool(tool: string) {
        let file: any;
        this.files.forEach(item => {
            if (item.tool == tool)
                file = item.file;
        })
        return file;
    }

    public async captureScreen() {
        if (this.platform.is('ios')) {
            // Comportamento specifico per iOS
            this.captureScreenIos();
        } else {
            // Comportamento per altre piattaforme
            this.captureScreenWeb();
        }
    }

    public captureScreenWeb() {
        const element = document.getElementById('export-report');
        if (!element) {
            console.error('Elemento HTML non trovato');
            return;
        }

        //dichiaro il filename con timestamp
        const timestamp = Date.now();
        const filename = `report_scan_${timestamp}.pdf`;

        var opt = {
            margin:       [20,0,20,0],
            filename:     filename,
            image:        { type: 'jpeg', quality: 1 },
            html2canvas:  { dpi:192, scale: 1, letterRendering: true, useCORS: true },
            jsPDF:        { unit: 'mm', format: 'a4', orientation: 'portrait' }
        };
        
        // New Promise-based usage:
        html2pdf().set(opt).from(element).save();
    }

    public async captureScreenIos() {
        // Seleziona l'elemento HTML da convertire in PDF
        const element = document.getElementById('export-report');
        if (!element) {
            console.error('Elemento HTML non trovato');
            return;
        }

        //Mostra la progress bar per l'export pdf
        this.isExportingPdf = true;
        // Forza il browser ad aggiornare il DOM prima di continuare
        await this.delay(100);

        //dichiaro il filename con timestamp
        const timestamp = Date.now();
        const filename = `report_scan_${timestamp}.pdf`;

        // Configurazione per html2pdf
        const opt = {
            margin: [20, 0, 20, 0],
            filename: filename,
            image: { type: 'jpeg', quality: 1 },
            html2canvas: { dpi: 192, scale: 1, letterRendering: true, useCORS: true },
            jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
        };

        try {
            // Aggiorna la progress bar al 50%
            this.pdfValue = 50;
            this.pdfStatus++;
            await this.delay(100);

            // Usa html2pdf per generare il PDF e ottenere un Blob
            const pdfBlob = await new Promise<Blob>((resolve, reject) => {
                html2pdf().from(element).set(opt).outputPdf().output('blob').then(resolve).catch(reject);
            });

            // Aggiorna la progress bar al 80%
            this.pdfValue = 80;
            await this.delay(100);

            // Converti il Blob in base64
            const reader = new FileReader();
            reader.readAsDataURL(pdfBlob);
            reader.onloadend = async () => {
                // Aggiorna entualmente la progress bar al 70%

                const base64Data = (reader.result as string).split(',')[1]; // Estrai la parte base64

                // Aggiorna la progress bar al 100%
                this.pdfValue = 100;
                this.pdfStatus++;
                await this.delay(100);

                // Salva il PDF nel filesystem
                try {
                    const result = await Filesystem.writeFile({
                        path: filename,
                        data: base64Data,
                        directory: Directory.Documents,
                        //encoding: Encoding.UTF8,
                    });
                    console.log('File salvato:', result);

                    this.isExportingPdf = false;

                    // Mostra un alert per confermare che il file è stato salvato
                    alert('Il file è stato salvato con successo nella cartella MVMR_ionic_client in File!');

                    // // Condividere il file
                    // await Share.share({
                    //     title: 'Condividi il PDF',
                    //     url: result.uri,
                    // });

                } catch (e) {
                    console.error('Errore nel salvare il file:', e);
                    // Nascondi la progress bar in caso di errore
                    this.isExportingPdf = false;
                }
            };

            reader.onerror = (error) => {
                console.error('Errore nella lettura del Blob:', error);
                // Nascondi la progress bar in caso di errore
                //this.hideProgressBar();
                this.isExportingPdf = false;
            };

        } catch (e) {
            console.error('Errore nella generazione del PDF:', e);
            // Nascondi la progress bar in caso di errore
            this.isExportingPdf = false;
        }
    }

    //Funzione per aggiornare il DOM per mostrare progress bar export pdf
    delay(ms: number) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }


    /*Resetta l'attività corrente per permettere una nuova scansione*/
    newSession() {
        //status
        this.status = 0; //man mano che vengono eseguite le tre fasi (merging, harvesting, bayesian) lo status viene incrementato

        //PROGRESS BAR
        this.color = 'primary';
        this.mode = 'buffer';
        this.value = 0;
        this.bufferValue = 0;

        //SEARCH FOR VULNERABILITIES BUTTON CHECK
        this.flag_vuln_button_clicked = false; //fin quando non viene caricato un file il pulsante non viene mostrato (si aggiorna in sendXMLs2Server() quando viene cliccato il pulsante)

        //Flag per i file selezionati
        this.flag_nmap = false;
        this.flag_openvas = false;
        this.flag_nessus = false;
        this.flag_owaspzap = false;

        //Flag per mostrare i risultati della scansione
        this.flag_show_report = false; //inizialmente non ci sono risultati quindi il report viene nascosto (si aggiorna in sendXMLs2Server() quando si ottengono i risultati finali)

        this.final_summary = {}

        this.xmls = []
        this.files.clear()
    }
}