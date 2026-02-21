/*
  VulnGuard — Taxonomy Mapper
  Maps vulnerability types → CWE → OWASP 2021
*/

function enrichWithTaxonomy(finding) {

  const taxonomyMap = {

    /* ================= INJECTION ================= */

    "SQL Injection": {
      cwe: "CWE-89",
      owasp: "A03:2021 - Injection"
    },

    "Cross-Site Scripting (XSS)": {
      cwe: "CWE-79",
      owasp: "A03:2021 - Injection"
    },

    "Command Injection (Inter-procedural)": {
      cwe: "CWE-78",
      owasp: "A03:2021 - Injection"
    },

    "NoSQL Injection": {
      cwe: "CWE-943",
      owasp: "A03:2021 - Injection"
    },

    "LDAP Injection": {
      cwe: "CWE-90",
      owasp: "A03:2021 - Injection"
    },

    "Template Injection": {
      cwe: "CWE-1336",
      owasp: "A03:2021 - Injection"
    },

    /* ================= ACCESS CONTROL ================= */

    "Missing Authorization Check": {
      cwe: "CWE-285",
      owasp: "A01:2021 - Broken Access Control"
    },

    "Insecure Direct Object Reference": {
      cwe: "CWE-639",
      owasp: "A01:2021 - Broken Access Control"
    },

    "Privilege Escalation": {
      cwe: "CWE-269",
      owasp: "A01:2021 - Broken Access Control"
    },

    /* ================= AUTHENTICATION ================= */

    "Weak Authentication": {
      cwe: "CWE-287",
      owasp: "A07:2021 - Identification and Authentication Failures"
    },

    "JWT None Algorithm": {
      cwe: "CWE-345",
      owasp: "A07:2021 - Identification and Authentication Failures"
    },

    "Hardcoded Credentials": {
      cwe: "CWE-798",
      owasp: "A07:2021 - Identification and Authentication Failures"
    },

    /* ================= SSRF ================= */

    "Server-Side Request Forgery (SSRF)": {
      cwe: "CWE-918",
      owasp: "A10:2021 - Server-Side Request Forgery"
    },

    /* ================= CRYPTO ================= */

    "Weak Cryptography": {
      cwe: "CWE-327",
      owasp: "A02:2021 - Cryptographic Failures"
    },

    "Insecure Randomness": {
      cwe: "CWE-330",
      owasp: "A02:2021 - Cryptographic Failures"
    },

    /* ================= DESERIALIZATION ================= */

    "Insecure Deserialization": {
      cwe: "CWE-502",
      owasp: "A08:2021 - Software and Data Integrity Failures"
    },

    /* ================= SECURITY MISCONFIG ================= */

    "Directory Traversal": {
      cwe: "CWE-22",
      owasp: "A05:2021 - Security Misconfiguration"
    },

    "Open Redirect": {
      cwe: "CWE-601",
      owasp: "A01:2021 - Broken Access Control"
    },

    /* ================= LOGIC FLAWS ================= */

    "Business Logic Flaw": {
      cwe: "CWE-840",
      owasp: "A04:2021 - Insecure Design"
    }

  };

  if (taxonomyMap[finding.type]) {
    return {
      ...finding,
      cwe: taxonomyMap[finding.type].cwe,
      owasp: taxonomyMap[finding.type].owasp
    };
  }

  return finding;
}

module.exports = { enrichWithTaxonomy };
