"""Authoritative OWASP Top 10:2025 catalog definitions."""

from typing import TypedDict


class OwaspCategoryRecord(TypedDict):
    code: str
    rank: int
    name: str
    name_es: str
    short_summary: str
    description: str
    remediation_guidance: str
    cwe_examples: list[str]
    is_new_in_2025: bool
    reference_url: str


OWASP_TOP_10_2025_CATALOG: list[OwaspCategoryRecord] = [
    {
        "code": "A01:2025",
        "rank": 1,
        "name": "Broken Access Control",
        "name_es": "Control de Acceso Roto",
        "short_summary": (
            "Fallos en la restricción de acciones autorizadas e inclusión explícita de "
            "Server-Side Request Forgery (SSRF)."
        ),
        "description": (
            "A01:2025 mantiene la primera posición e incorpora oficialmente las vulnerabilidades "
            "SSRF (CWE-918). Incluye la exposición no autorizada de paneles administrativos, "
            "endpoints sensibles sin control de acceso, elevación de privilegios, omisión de "
            "políticas CORS y acceso indebido a recursos internos."
        ),
        "remediation_guidance": (
            "Aplicar denegación por defecto (deny-by-default), restringir el acceso administrativo "
            "por red/VPN o mTLS, validar autorizaciones en servidor en cada petición, deshabilitar "
            "listado de directorios y bloquear resoluciones hacia rangos IP privados/metadata (SSRF)."
        ),
        "cwe_examples": ["CWE-200", "CWE-284", "CWE-285", "CWE-352", "CWE-639", "CWE-918"],
        "is_new_in_2025": False,
        "reference_url": "https://owasp.org/Top10/2025/",
    },
    {
        "code": "A02:2025",
        "rank": 2,
        "name": "Security Misconfiguration",
        "name_es": "Configuración de Seguridad Incorrecta",
        "short_summary": (
            "Configuraciones inseguras por defecto, puertos innecesarios, cabeceras defensivas "
            "ausentes y registros DNS sin endurecimiento."
        ),
        "description": (
            "A02:2025 asciende a la segunda posición al cubrir configuraciones incompletas o "
            "permisivas en infraestructura, servidores web, DNS (SPF/DMARC ausentes o permisivos), "
            "puertos o servicios innecesarios expuestos y ausencia de cabeceras de seguridad HTTP."
        ),
        "remediation_guidance": (
            "Implementar procesos repetibles de hardening, cerrar puertos no esenciales mediante "
            "firewall, configurar cabeceras HTTP defensivas (CSP, HSTS, X-Frame-Options, "
            "X-Content-Type-Options, Referrer-Policy, Permissions-Policy), suprimir banners de "
            "versión y publicar registros SPF (-all) y DMARC (p=quarantine/reject)."
        ),
        "cwe_examples": ["CWE-16", "CWE-611", "CWE-693", "CWE-942", "CWE-1004", "CWE-1275"],
        "is_new_in_2025": False,
        "reference_url": "https://owasp.org/Top10/2025/",
    },
    {
        "code": "A03:2025",
        "rank": 3,
        "name": "Software Supply Chain Failures",
        "name_es": "Fallos en la Cadena de Suministro de Software",
        "short_summary": (
            "Riesgos derivados de dependencias vulnerables, librerías desactualizadas, scripts "
            "externos no controlados y artefactos de terceros sin verificación."
        ),
        "description": (
            "Nueva categoría ampliada en OWASP Top 10:2025 que reemplaza y extiende a componentes "
            "vulnerables y desactualizados. Abarca frameworks, CMS, librerías frontend/JS y "
            "servidores web con CVEs conocidos o sin gestión controlada de versiones y origen."
        ),
        "remediation_guidance": (
            "Mantener un inventario continuo (SBOM) de dependencias y servidores, actualizar a "
            "versiones soportadas libres de CVEs críticos/altos, fijar versiones con checksums "
            "y restringir orígenes de scripts externos mediante CSP y Subresource Integrity (SRI)."
        ),
        "cwe_examples": ["CWE-1104", "CWE-1329", "CWE-1357", "CWE-1395"],
        "is_new_in_2025": True,
        "reference_url": "https://owasp.org/Top10/2025/",
    },
    {
        "code": "A04:2025",
        "rank": 4,
        "name": "Cryptographic Failures",
        "name_es": "Fallos Criptográficos",
        "short_summary": (
            "Uso de protocolos TLS obsoletos, cifrados débiles, certificados expirados o "
            "transmisión de datos sensibles sin cifrado robusto."
        ),
        "description": (
            "Cubre fallos relacionados con criptografía en tránsito o reposo: soporte de SSLv3, "
            "TLS 1.0/1.1, suites de cifrado con RC4/3DES/CBC débil, ausencia de Forward Secrecy, "
            "certificados caducados/autofirmados o redirección HTTPS ausente."
        ),
        "remediation_guidance": (
            "Habilitar exclusivamente TLS 1.2 y TLS 1.3 con suites AEAD modernas (ECDHE-ECDSA/RSA "
            "con AES-GCM o ChaCha20-Poly1305), renovar certificados antes de su expiración, "
            "aplicar HSTS con max-age >= 31536000 y validar cadenas de confianza completas."
        ),
        "cwe_examples": ["CWE-295", "CWE-319", "CWE-326", "CWE-327", "CWE-328", "CWE-757"],
        "is_new_in_2025": False,
        "reference_url": "https://owasp.org/Top10/2025/",
    },
    {
        "code": "A05:2025",
        "rank": 5,
        "name": "Injection",
        "name_es": "Inyección",
        "short_summary": (
            "Vulnerabilidades de inyección de código, comandos o scripts (incluyendo XSS) por "
            "ausencia de saneamiento, parametrización o defensas CSP."
        ),
        "description": (
            "Incluye Cross-Site Scripting (XSS), inyección de comandos del sistema operativo, "
            "SQL Injection y otras inyecciones cuando datos no confiables se interpretan como "
            "instrucciones o cuando faltan controles defensivos como Content-Security-Policy."
        ),
        "remediation_guidance": (
            "Utilizar consultas parametrizadas y listas de argumentos sin shell (shell=False), "
            "aplicar codificación contextual estricta en salidas HTML/JS y desplegar una política "
            "Content-Security-Policy (CSP) restrictiva sin 'unsafe-inline' ni 'unsafe-eval'."
        ),
        "cwe_examples": ["CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94"],
        "is_new_in_2025": False,
        "reference_url": "https://owasp.org/Top10/2025/",
    },
    {
        "code": "A06:2025",
        "rank": 6,
        "name": "Insecure Design",
        "name_es": "Diseño Inseguro",
        "short_summary": (
            "Deficiencias arquitectónicas y ausencia de controles preventivos desde el diseño "
            "del sistema."
        ),
        "description": (
            "Representa fallos estructurales derivados de la falta de modelado de amenazas, "
            "ausencia de límites de confianza, exposición innecesaria de flujos críticos o "
            "carencia de controles defensivos por diseño."
        ),
        "remediation_guidance": (
            "Incorporar modelado de amenazas en el ciclo SDLC, segregar planos de administración "
            "respecto a planos públicos, aplicar límites de tasa (rate limiting) y establecer "
            "patrones seguros reutilizables."
        ),
        "cwe_examples": ["CWE-209", "CWE-256", "CWE-501", "CWE-522", "CWE-799"],
        "is_new_in_2025": False,
        "reference_url": "https://owasp.org/Top10/2025/",
    },
    {
        "code": "A07:2025",
        "rank": 7,
        "name": "Authentication Failures",
        "name_es": "Fallos de Autenticación",
        "short_summary": (
            "Debilidades en gestión de sesiones, cookies sin protección y mecanismos de "
            "autenticación expuestos."
        ),
        "description": (
            "Renombrada en 2025 desde Identification and Authentication Failures. Abarca cookies "
            "de sesión sin flags HttpOnly, Secure o SameSite, fijación de sesión, exposición "
            "de interfaces de autenticación sin cifrado o falta de controles anti-fuerza bruta."
        ),
        "remediation_guidance": (
            "Configurar todas las cookies de sesión con Secure, HttpOnly y SameSite=Lax/Strict, "
            "rotar identificadores de sesión tras el inicio de sesión, exigir MFA en accesos "
            "privilegiados y proteger formularios sobre HTTPS estricto."
        ),
        "cwe_examples": ["CWE-287", "CWE-306", "CWE-384", "CWE-613", "CWE-798"],
        "is_new_in_2025": False,
        "reference_url": "https://owasp.org/Top10/2025/",
    },
    {
        "code": "A08:2025",
        "rank": 8,
        "name": "Software or Data Integrity Failures",
        "name_es": "Fallos de Integridad de Software y Datos",
        "short_summary": (
            "Carga de recursos o actualizaciones sin verificación criptográfica de integridad "
            "(como ausencia de Subresource Integrity - SRI)."
        ),
        "description": (
            "Se produce cuando las aplicaciones confían en scripts externos, CDNs, plugins o "
            "pipelines sin validar su integridad criptográfica mediante hashes o firmas, "
            "exponiéndose a manipulación en tránsito o compromiso de terceros."
        ),
        "remediation_guidance": (
            "Añadir atributos integrity (SHA-384/SHA-512) y crossorigin='anonymous' (SRI) en "
            "todos los recursos externos <script> y <link>, firmar artefactos desplegados y "
            "restringir orígenes permitidos mediante CSP."
        ),
        "cwe_examples": ["CWE-345", "CWE-353", "CWE-494", "CWE-502", "CWE-829"],
        "is_new_in_2025": False,
        "reference_url": "https://owasp.org/Top10/2025/",
    },
    {
        "code": "A09:2025",
        "rank": 9,
        "name": "Security Logging and Alerting Failures",
        "name_es": "Fallos en el Registro y Alerta de Seguridad",
        "short_summary": (
            "Ausencia de bitácoras estructuradas, trazabilidad de eventos críticos y mecanismos "
            "de alerta ante anomalías."
        ),
        "description": (
            "Impide detectar, investigar y responder a incidentes de seguridad cuando fallan los "
            "registros de eventos relevantes (autorizaciones, bloqueos SSRF, errores críticos) "
            "o carecen de formato estructurado e integridad."
        ),
        "remediation_guidance": (
            "Registrar en formato estructurado (JSON) los eventos de autenticación, autorización, "
            "validación de entrada y errores críticos sin filtrar secretos/PII, centralizar logs "
            "y definir alertas automáticas ante patrones anómalos."
        ),
        "cwe_examples": ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        "is_new_in_2025": False,
        "reference_url": "https://owasp.org/Top10/2025/",
    },
    {
        "code": "A10:2025",
        "rank": 10,
        "name": "Mishandling of Exceptional Conditions",
        "name_es": "Manejo Incorrecto de Condiciones Excepcionales",
        "short_summary": (
            "Exposición de stack traces o detalles internos de error, fallos en modo abierto "
            "(fail-open) y gestión deficiente de excepciones."
        ),
        "description": (
            "Nueva categoría introducida en OWASP Top 10:2025 centrada en errores no controlados, "
            "filtración de trazas de depuración (stack traces, rutas internas, queries SQL) hacia "
            "el cliente y estados inconsistentes ante condiciones límite."
        ),
        "remediation_guidance": (
            "Desactivar modos debug en producción, implementar manejadores globales de excepciones "
            "que devuelvan mensajes genéricos al usuario con ID de correlación, registrar el "
            "detalle internamente y garantizar comportamiento fail-closed."
        ),
        "cwe_examples": ["CWE-209", "CWE-248", "CWE-476", "CWE-636", "CWE-755"],
        "is_new_in_2025": True,
        "reference_url": "https://owasp.org/Top10/2025/",
    },
]
