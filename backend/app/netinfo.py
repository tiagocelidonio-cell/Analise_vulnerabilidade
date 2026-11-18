"""Ferramenta de rede (passiva, estilo MXToolbox): consulta DNS, identifica onde
o domínio está hospedado, o provedor de DNS, CDN/WAF e a segurança de e-mail.

Tudo é informação PÚBLICA (DNS + cabeçalhos HTTP) — não-intrusivo, sem varredura
de portas nem exploração. Serve ao reconhecimento e à triagem.
"""
from __future__ import annotations

import re

import httpx

# ---- Impressões digitais (fingerprints) --------------------------------------

# Hospedagem / nuvem, por PTR (DNS reverso), CNAME ou nameserver.
_HOSTING = [
    ("Amazon AWS", ("amazonaws.com", "aws.", "compute.amazonaws.com", "elb.amazonaws.com")),
    ("Amazon CloudFront", ("cloudfront.net",)),
    ("Google Cloud", ("googleusercontent.com", "1e100.net", "goog", "google.com")),
    ("Microsoft Azure", ("azure", "cloudapp.azure.com", "azurewebsites.net", "azureedge.net", "trafficmanager.net")),
    ("Cloudflare", ("cloudflare", "cloudflare.net")),
    ("GitHub Pages", ("github.io", "github.com", "fastly")),
    ("Netlify", ("netlify",)),
    ("Vercel", ("vercel", "vercel-dns")),
    ("Heroku", ("herokuapp.com", "herokudns.com")),
    ("DigitalOcean", ("digitalocean.com", "digitaloceanspaces.com")),
    ("OVH", ("ovh.net", "ovh.com")),
    ("Hetzner", ("hetzner.com", "your-server.de")),
    ("Oracle Cloud", ("oraclecloud.com",)),
    ("Akamai", ("akamai", "akamaiedge.net", "edgekey.net", "edgesuite.net")),
    ("Fastly", ("fastly.net", "fastlylb.net")),
    ("Locaweb", ("locaweb.com.br",)),
    ("UOL Host", ("uolhost.com.br", "uol.com.br")),
    ("KingHost", ("kinghost.net",)),
    ("HostGator", ("hostgator.com.br", "websitewelcome.com")),
]

# Provedor de DNS autoritativo, pelos nameservers (NS).
_DNS_PROVIDER = [
    ("Cloudflare DNS", ("cloudflare.com",)),
    ("AWS Route 53", ("awsdns",)),
    ("Azure DNS", ("azure-dns",)),
    ("Google Cloud DNS", ("googledomains.com", "ns-cloud", "google.com")),
    ("NS1", ("nsone.net",)),
    ("GoDaddy", ("domaincontrol.com",)),
    ("Namecheap", ("registrar-servers.com",)),
    ("DNSimple", ("dnsimple.com",)),
    ("Dyn", ("dynect.net",)),
    ("Registro.br", ("dns.br", "registro.br")),
    ("Locaweb", ("locaweb.com.br",)),
    ("UOL", ("uolhost.com.br",)),
]

# CDN / WAF, por cabeçalho, cookie ou CNAME. (header_substrings, cookie_substrings, cname_substrings)
_CDN_WAF = [
    ("Cloudflare", ["cf-ray", "cloudflare"], ["__cfduid", "__cf_bm", "cf_clearance"], ["cloudflare"]),
    ("Akamai", ["akamaighost", "x-akamai", "akamai"], ["ak_bmsc", "akavpau"], ["akamai", "edgekey.net", "edgesuite.net"]),
    ("Amazon CloudFront", ["x-amz-cf-id", "cloudfront"], [], ["cloudfront.net"]),
    ("AWS WAF / ALB", ["x-amzn", "awselb"], ["awsalb", "awsalbcors"], ["elb.amazonaws.com"]),
    ("Imperva Incapsula", ["x-iinfo", "incapsula", "x-cdn"], ["incap_ses", "visid_incap", "nlbi_"], ["incapdns", "imperva"]),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache", "sucuri/cloudproxy"], [], ["sucuri.net"]),
    ("F5 BIG-IP ASM", ["bigipserver", "x-waf-event"], ["bigipserver", "ts01", "f5avr"], []),
    ("Fastly", ["x-served-by", "x-fastly", "fastly"], [], ["fastly.net"]),
    ("Azure Front Door", ["x-azure-ref", "x-fd-"], [], ["azureedge.net", "azurefd.net", "trafficmanager.net"]),
    ("Barracuda", ["barracuda"], ["barra_counter_session"], ["barracudanetworks.com"]),
    ("Sucuri/ModSecurity", ["mod_security", "modsecurity", "naxsi"], [], []),
    ("Google Cloud", ["gws", "google frontend", "via: 1.1 google"], [], []),
    ("Vercel", ["x-vercel-id", "server: vercel"], [], ["vercel"]),
    ("Netlify", ["x-nf-request-id", "server: netlify"], [], ["netlify"]),
    ("StackPath / Highwinds", ["x-hw", "stackpath"], [], ["stackpathdns.com"]),
]

# Segurança de e-mail (gateway), pelos registros MX.
_EMAIL_SEC = [
    ("Microsoft 365 / Exchange Online", ("mail.protection.outlook.com", "outlook.com")),
    ("Google Workspace", ("google.com", "googlemail.com", "aspmx.l.google.com")),
    ("Proofpoint", ("pphosted.com", "ppe-hosted.com")),
    ("Mimecast", ("mimecast.com", "mimecast.co")),
    ("Barracuda", ("barracudanetworks.com", "barracuda.com")),
    ("Cisco Secure Email (IronPort)", ("iphmx.com", "cisco.com")),
    ("Trend Micro", ("trendmicro.com", "trendmicro.eu")),
    ("Sophos", ("sophos.com",)),
    ("Zix / AppRiver", ("zixport.com", "arsmtp.com")),
    ("Fortinet FortiMail", ("fortimail", "fortinet.com")),
    ("Locaweb E-mail", ("locaweb.com.br",)),
    ("UOL", ("uol.com.br",)),
]

# Pistas em SPF (include:) sobre quem envia o e-mail do domínio.
_SPF_HINTS = [
    ("Microsoft 365", ("spf.protection.outlook.com",)),
    ("Google Workspace", ("_spf.google.com",)),
    ("Proofpoint", ("pphosted.com", "ppe-hosted.com")),
    ("Mimecast", ("mimecast.com",)),
    ("Amazon SES", ("amazonses.com",)),
    ("SendGrid", ("sendgrid.net",)),
    ("Mailgun", ("mailgun.org",)),
    ("Mailchimp/Mandrill", ("mandrillapp.com", "mcsv.net")),
    ("Zoho", ("zoho.com", "zoho.eu")),
    ("Salesforce", ("salesforce.com", "_spf.salesforce.com")),
]

# Pistas de verificação em TXT (ferramentas/serviços em uso no domínio).
_VERIFY_HINTS = [
    ("Microsoft 365", ("ms=",)),
    ("Google", ("google-site-verification",)),
    ("Atlassian", ("atlassian-domain-verification",)),
    ("Facebook/Meta", ("facebook-domain-verification",)),
    ("Adobe", ("adobe-idp-site-verification",)),
    ("DocuSign", ("docusign",)),
    ("Zoom", ("zoom",)),
    ("Stripe", ("stripe-verification",)),
    ("Amazon SES", ("amazonses",)),
    ("Cisco Webex", ("cisco-ci-domain-verification", "webexdomainverification")),
    ("Dropbox", ("dropbox-domain-verification",)),
    ("Miro", ("miro-verification",)),
    ("Notion", ("notion",)),
]

# DMARC: destino dos relatórios (rua/ruf) revela a plataforma de monitoramento.
_DMARC_HINTS = [
    ("Proofpoint", ("dmarc.proofpoint.com",)),
    ("Agari", ("rua.agari.com",)),
    ("Dmarcian", ("dmarcian.com",)),
    ("Red Sift OnDMARC", ("ondmarc.redsift.com",)),
    ("Valimail", ("valimail.com",)),
    ("Mimecast", ("mimecast",)),
    ("Microsoft", ("outlook.com",)),
]


async def _resolve(domain: str, rtype: str) -> list[str]:
    """Resolve pelo resolver do sistema; se falhar/vier vazio, tenta resolvers
    públicos (1.1.1.1 / 8.8.8.8) — mais robusto em ambientes restritos."""
    import dns.asyncresolver

    async def _try(nameservers=None):
        r = dns.asyncresolver.Resolver()
        r.timeout = 4
        r.lifetime = 6
        if nameservers:
            r.nameservers = nameservers
        try:
            ans = await r.resolve(domain, rtype)
            return [str(x).rstrip(".").strip() for x in ans]
        except Exception:  # noqa: BLE001
            return []

    out = await _try()
    if not out:
        out = await _try(["1.1.1.1", "8.8.8.8"])
    return out


async def _ptr(ip: str) -> str | None:
    import dns.asyncresolver
    import dns.reversename
    try:
        name = dns.reversename.from_address(ip)
        r = dns.asyncresolver.Resolver()
        r.timeout = 3
        r.lifetime = 5
        ans = await r.resolve(name, "PTR")
        return str(ans[0]).rstrip(".")
    except Exception:  # noqa: BLE001
        return None


def _match(hay: str, table: list) -> list[str]:
    hay = (hay or "").lower()
    out = []
    for name, needles in table:
        if any(n.lower() in hay for n in needles):
            out.append(name)
    return out


def _host_only(target: str) -> str:
    t = (target or "").strip()
    t = t.split("://")[-1].split("/")[0].split("?")[0]
    t = t.split("@")[-1].split(":")[0].strip().strip(".")
    return t.lower()


async def _waf_probe(domain: str) -> dict:
    """Busca cabeçalhos/cookies (https depois http) para identificar CDN/WAF."""
    out = {"reachable": False, "server": None, "headers": {}, "detected": []}
    for scheme in ("https", "http"):
        try:
            async with httpx.AsyncClient(verify=False, timeout=8,
                                         follow_redirects=True, max_redirects=4,
                                         headers={"User-Agent": "Mozilla/5.0 VulnScope"}) as c:
                r = await c.get(f"{scheme}://{domain}/")
        except Exception:  # noqa: BLE001
            continue
        out["reachable"] = True
        hdr_blob = " ".join(f"{k}: {v}" for k, v in r.headers.items())
        cookies = " ".join(r.headers.get_list("set-cookie")) if hasattr(r.headers, "get_list") else ""
        out["server"] = r.headers.get("server")
        # Cabeçalhos mais reveladores para mostrar na UI.
        for h in ("server", "via", "x-cache", "x-cdn", "cf-ray", "x-amz-cf-id",
                  "x-served-by", "x-azure-ref", "x-iinfo", "x-sucuri-id",
                  "x-powered-by", "x-akamai-transformed"):
            if h in r.headers:
                out["headers"][h] = r.headers[h]
        found = set()
        for name, hsubs, csubs, _cn in _CDN_WAF:
            blob = hdr_blob.lower()
            ck = cookies.lower()
            if any(s in blob for s in hsubs) or any(s in ck for s in csubs):
                found.add(name)
        out["detected"] = sorted(found)
        return out
    return out


async def network_lookup(target: str) -> dict:
    """Consulta de rede completa (DNS + hospedagem + CDN/WAF + e-mail)."""
    domain = _host_only(target)
    if not domain or "." not in domain:
        return {"error": "Informe um domínio válido (ex.: exemplo.com.br)."}

    a = await _resolve(domain, "A")
    aaaa = await _resolve(domain, "AAAA")
    mx = await _resolve(domain, "MX")
    ns = await _resolve(domain, "NS")
    txt = await _resolve(domain, "TXT")
    soa = await _resolve(domain, "SOA")
    cname = await _resolve(domain, "CNAME")
    caa = await _resolve(domain, "CAA")
    dmarc = await _resolve(f"_dmarc.{domain}", "TXT")
    # www costuma revelar o CDN via CNAME.
    www_cname = await _resolve(f"www.{domain}", "CNAME")

    # PTR dos IPs (até 4).
    ptrs = {}
    for ip in a[:4]:
        p = await _ptr(ip)
        if p:
            ptrs[ip] = p

    # Fingerprints.
    host_blob = " ".join(a + list(ptrs.values()) + cname + www_cname + ns)
    hosting = _match(host_blob, _HOSTING)
    dns_provider = _match(" ".join(ns), _DNS_PROVIDER)
    email_sec = _match(" ".join(mx), _EMAIL_SEC)

    spf = next((t for t in txt if "v=spf1" in t.lower()), None)
    spf_providers = _match(spf or "", _SPF_HINTS)
    verifications = _match(" ".join(txt), _VERIFY_HINTS)
    dmarc_rec = next((t for t in dmarc if "v=dmarc1" in t.lower()), None)
    dmarc_monitor = _match(dmarc_rec or "", _DMARC_HINTS)

    # WAF/CDN por cabeçalhos + por CNAME.
    waf = await _waf_probe(domain)
    cname_blob = " ".join(cname + www_cname).lower()
    for name, _h, _c, cnsubs in _CDN_WAF:
        if cnsubs and any(s in cname_blob for s in cnsubs) and name not in waf["detected"]:
            waf["detected"].append(name)
    waf["detected"] = sorted(set(waf["detected"]))

    # Sinais de postura de segurança.
    posture = {
        "spf": bool(spf),
        "dmarc": bool(dmarc_rec),
        "dmarc_policy": (re.search(r"p=(\w+)", dmarc_rec).group(1)
                         if dmarc_rec and re.search(r"p=(\w+)", dmarc_rec) else None),
        "caa": bool(caa),
        "dnssec": bool(await _resolve(domain, "DNSKEY")),
    }

    return {
        "domain": domain,
        "records": {
            "A": a, "AAAA": aaaa, "MX": mx, "NS": ns, "TXT": txt,
            "SOA": soa, "CNAME": cname, "CAA": caa, "DMARC": dmarc,
            "www_CNAME": www_cname, "PTR": ptrs,
        },
        "hosting": hosting,
        "dns_provider": dns_provider,
        "cdn_waf": {"detected": waf["detected"], "server": waf.get("server"),
                    "headers": waf.get("headers", {}), "reachable": waf.get("reachable")},
        "email_security": {"gateways": email_sec, "spf_providers": spf_providers,
                           "spf": spf},
        "security_tools": {"verifications": verifications,
                           "dmarc_monitoring": dmarc_monitor},
        "posture": posture,
    }
