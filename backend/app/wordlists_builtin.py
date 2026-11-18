"""Listas públicas embutidas para o ataque de credenciais (curadas, estilo
SecLists / credenciais padrão conhecidas). Semeadas no banco na inicialização.

São dados públicos consagrados em pentests autorizados. O operador pode duplicar
e editar, e combinar com listas próprias ou importadas.
"""
from __future__ import annotations

# Senhas mais comuns (curado, público).
_TOP_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345", "1234567", "qwerty",
    "abc123", "password1", "1234567890", "123123", "000000", "iloveyou", "1234",
    "1q2w3e4r", "admin", "qwertyuiop", "123321", "111111", "senha", "senha123",
    "mudar123", "brasil", "brasil123", "123mudar", "102030", "112233", "zxcvbnreel",
    "zxcvbnm", "asdfghjkl", "qwerty123", "1qaz2wsx", "dragon", "monkey", "letmein",
    "football", "welcome", "login", "princess", "solo", "admin123", "root",
    "toor", "pass", "test", "test123", "guest", "master", "superman", "michael",
    "shadow", "sunshine", "654321", "666666", "7777777", "888888", "qazwsx",
    "changeme", "default", "secret", "god", "love", "money", "server", "oracle",
    "mysql", "postgres", "redis", "ubuntu", "centos", "debian", "jenkins",
    "tomcat", "manager", "administrator", "user", "P@ssw0rd", "P@ssword",
    "Passw0rd", "Password1", "Password123", "Welcome1", "Welcome123", "Admin@123",
    "Admin123", "Abcd1234", "abcd1234", "trustno1", "whatever", "hello", "hello123",
    "freedom", "ninja", "azerty", "flower", "hottie", "loveme", "zaq12wsx",
    "passw0rd", "starwars", "cheese", "computer", "internet", "service", "access",
    "michelle", "jordan", "tigger", "charlie", "robert", "thomas", "daniel",
    "ashley", "bailey", "jessica", "amanda", "summer", "george", "andrew",
    "123qwe", "qwe123", "a123456", "123abc", "1q2w3e", "q1w2e3r4", "1111",
    "0000", "2020", "2021", "2022", "2023", "2024", "mudar@123", "empresa123",
]

# Usuários comuns.
_TOP_USERS = [
    "admin", "administrator", "root", "user", "test", "guest", "operator",
    "manager", "support", "sysadmin", "oracle", "postgres", "mysql", "ftp",
    "www", "web", "backup", "tomcat", "jenkins", "git", "deploy", "service",
    "adm", "suporte", "usuario", "financeiro", "ti", "contato", "info",
]

# Pares usuário:senha padrão consagrados (default credentials).
_DEFAULT_PAIRS = [
    "admin:admin", "admin:password", "admin:admin123", "admin:1234",
    "admin:123456", "admin:changeme", "admin:", "administrator:administrator",
    "administrator:password", "root:root", "root:toor", "root:password",
    "root:admin", "user:user", "test:test", "guest:guest", "operator:operator",
    "tomcat:tomcat", "tomcat:s3cret", "manager:manager", "oracle:oracle",
    "postgres:postgres", "mysql:mysql", "sa:sa", "sa:", "ftp:ftp",
    "anonymous:anonymous", "pi:raspberry", "ubnt:ubnt", "cisco:cisco",
    "jenkins:jenkins", "grafana:admin", "kibana:kibana", "zabbix:zabbix",
]

BUILTIN_LISTS = [
    {"name": "Senhas comuns (público)", "kind": "passwords",
     "content": "\n".join(_TOP_PASSWORDS)},
    {"name": "Usuários comuns (público)", "kind": "users",
     "content": "\n".join(_TOP_USERS)},
    {"name": "Credenciais padrão / default (público)", "kind": "pairs",
     "content": "\n".join(_DEFAULT_PAIRS)},
]


async def seed_builtin_wordlists(session) -> None:
    """Cria as listas públicas embutidas se ainda não existirem (por nome)."""
    from sqlalchemy import select

    from app.models import CredentialList
    for spec in BUILTIN_LISTS:
        exists = await session.scalar(
            select(CredentialList).where(CredentialList.name == spec["name"],
                                         CredentialList.builtin.is_(True)))
        if exists is None:
            n = sum(1 for ln in spec["content"].splitlines() if ln.strip())
            session.add(CredentialList(
                name=spec["name"], kind=spec["kind"], content=spec["content"],
                builtin=True, count=n, created_by=None))
    await session.commit()
