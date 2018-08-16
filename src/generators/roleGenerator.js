
class RoleGenerator {
    constructor(vaultClient) {
        this.vaultClient = vaultClient;
    }

    apply(cert) {
        return Promise.all(cert.spec.roles.map((role) => this.generateRole(cert, role)))
    }

    generateRole(cert, role) {
        let {
            name,
            ttl,
            maxTtl,
            allowLocalhost,
            allowedDomains,
            allowBareDomains,
            allowSubdomains,
            allowGlobDomains,
            allowAnyName,
            enforceHostnames,
            allowIpSans,
            allowedUriSans,
            allowedOtherSans,
            serverFlag,
            clientFlag,
            codeSigningFlag,
            emailProtectionFlag,
            keyType,
            keyBits,
            keyUsage,
            extKeyUsage,
            useCsrCommonName,
            useCsrSans,
            ou,
            organization,
            country,
            locality,
            province,
            streetAddress,
            postalCode,
            generateLease,
            noStore,
            requireCn,
            policyIdentifiers,
            basicConstraintsValidForNonCa
        } = role;
        return this.vaultClient.write(`${cert.spec.path}/roles/${name}`, {
            ttl,
            maxTtl,
            allow_localhost: allowLocalhost,
            allowed_domains: allowedDomains,
            allow_bare_domains: allowBareDomains,
            allow_subdomains: allowSubdomains,
            allow_glob_domains: allowGlobDomains,
            allow_any_name: allowAnyName,
            enforce_hostnames: enforceHostnames,
            allow_ip_sans: allowIpSans,
            allowed_uri_sans: allowedUriSans,
            allowed_other_sans: allowedOtherSans,
            server_flag: serverFlag,
            client_flag: clientFlag,
            code_signing_flag: codeSigningFlag,
            email_protection_flag: emailProtectionFlag,
            key_type: keyType,
            key_bits: keyBits,
            key_usage: keyUsage,
            ext_key_usage: extKeyUsage,
            use_csr_common_name: useCsrCommonName,
            use_csr_sans: useCsrSans,
            ou,
            organization,
            country,
            locality,
            province,
            street_address: streetAddress,
            postal_code: postalCode,
            generate_lease: generateLease,
            no_store: noStore,
            require_cn: requireCn,
            policy_identifiers: policyIdentifiers,
            basic_constraints_valid_for_non_ca: basicConstraintsValidForNonCa
        })
    }
}

module.exports = RoleGenerator;