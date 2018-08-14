const VaultClient = require("node-vault");
const fs = require('fs');

class VaultHelper {
    constructor() {
        this.vaultClient = VaultClient({
            apiVersion: 'v1',
            endpoint: `https://${process.env.VAULT_HOST}:${process.env.VAULT_PORT}`,
            token: process.env.VAULT_TOKEN,
            requestOptions: {
                ca: fs.readFileSync(process.env.VAULT_TLS_CA),
            }
        })
    }

    applyPolicy(policy) {
        let {
            name,
            rules
        } = policy.spec;
        let rulesObject = {};
        rules.forEach(rule => {
            let {
                path,
                capabilities,
                minWrappingTtl,
                maxWrappingTtl,
                allowedParameters,
                deniedParameters,
                requiredParameters
            } = rule;
            rulesObject[path] = {
                capabilities,
                required_parameters: requiredParameters,
                allowed_parameters: allowedParameters,
                denied_parameters: deniedParameters,
                min_wrapping_ttl: minWrappingTtl,
                max_wrapping_ttl: maxWrappingTtl
            };
        });
        return this.vaultClient.addPolicy({
            name,
            rules: JSON.stringify({path: rulesObject}, null, 4),
        });
    }

    deletePolicy(policy) {
        let {name} = policy.spec;
        return this.vaultClient.removePolicy({name})
    }

    applySecretEngine(secretEngine) {
        let {
            path,
            type,
            description,
            config,
            options,
            local,
            sealWrap
        } = secretEngine.spec;
        let {
            defaultLeaseTtl,
            maxLeaseTtl,
            forceNoCache,
            pluginName,
            auditNonHmacRequestKeys,
            auditNonHmacResponseKeys,
            listingVisibility,
            passthroughRequestHeaders
        } = config;
        return this.vaultClient.mount({
            mount_point: path,
            type,
            description,
            config: {
                default_lease_ttl: defaultLeaseTtl,
                max_lease_ttl: maxLeaseTtl,
                force_no_cache: forceNoCache,
                plugin_name: pluginName,
                audit_non_hmac_request_keys: (auditNonHmacRequestKeys || []).concat(','),
                audit_non_hmac_response_keys: (auditNonHmacResponseKeys || []).concat(','),
                listing_visibility: listingVisibility,
                passthrough_request_headers: (passthroughRequestHeaders || []).concat(',')
            },
            options,
            plugin_name: secretEngine.spec.pluginName,
            local,
            seal_wrap: sealWrap
        }).catch(() => console.log(`Secret Engine ${secretEngine.metadata.name}, path ${path} already exist`))
    }

    applyRootCa(cert) {
        let {pemBundle, generate} = cert.spec;
        if (pemBundle) {
            return this.vaultClient.write(`${cert.spec.path}/config/ca`, {
                pem_bundle: pemBundle
            });
        } else if (generate) {
            return this.generateRootCa(cert, generate);
        }
    }

    applyIntermediateCa(cert) {
        let {certificate, generate} = cert.spec;
        if (certificate) {
            return this.vaultClient.write(`${cert.spec.path}/intermediate/set-signed`, {
                certificate
            });
        } else if (generate) {
            let commonName = generate.commonName;
            return this.generateIntermediateCa(cert, generate)
                .then((generated) => {
                    if (generated) {
                        let csr = generated.data.csr;
                        if (csr) {
                            console.log(`Certificate for ${commonName} generated`);
                            return this.signIntermediate(cert, csr).then((intermediateCert) => {
                                let certificate = intermediateCert.data.certificate;
                                if (certificate) {
                                    console.log(`Certificate for ${commonName} signed with root certificate`);
                                    return this.vaultClient.write(`${cert.spec.path}/intermediate/set-signed`, { certificate })
                                } else {
                                    console.log(`Unable to sign certificate for ${commonName} with root certificate`);
                                }
                            })
                        } else {
                            console.log(`Unable to generate certificate for ${commonName}`)
                        }
                    } else {
                        console.log(`Certificate already exists for ${commonName}`)
                    }
                });
        }
    }

    recordSerial(path, namespace, name, serialNumber, revoked) {
        return this.vaultClient.write(`secret/data/serials/${path}/${namespace}/${name}`, {data: {serialNumber, revoked}})
    }

    applyCa(cert, onGenerated) {
        let {secretName, generate} = cert.spec;
        let commonName = generate.commonName;
        return this.vaultClient.read(`secret/data/serials/${cert.spec.path}/${cert.metadata.namespace || "default"}/${cert.metadata.name}`).catch(() => {
            return this.generateCertificate(cert, generate)
                .then((generated) => {
                    if (generated) {
                        let {certificate, ca_chain, private_key, serial_number} = generated.data;
                        if (certificate) {
                            console.log(`Certificate for ${commonName} generated`);
                            return this.recordSerial(cert.spec.path, cert.metadata.namespace || "default", cert.metadata.name, serial_number, false)
                                .then(() => onGenerated(secretName, cert.metadata.namespace || "default", ca_chain.join('\n'), certificate, private_key));
                        } else {
                            console.log(`Unable to generate certificate for ${commonName}`)
                        }
                    } else {
                        console.log(`Certificate already exists for ${commonName}`)
                    }
                })
        })
    }

    revokeCa(cert) {
        let namespace = cert.metadata.namespace || "default";
        return this.vaultClient.read(`secret/data/serials/${cert.spec.path}/${namespace}/${cert.metadata.name}`).then((serial) => {
            if (serial.data.revoked) {
                console.log("Certificate already revoked")
            } else {
                return this.vaultClient.write(`${cert.spec.path}/revoke`, {serial_number: serial.data.serialNumber})
                    .then(() => this.recordSerial(cert.spec.path, namespace, cert.metadata.name, serial.data.serialNumber, true))
            }
        });
    }

    applyRoles(cert) {
        return Promise.all(cert.spec.roles.map((role) => this.generateRole(cert, role)))
    }

    signIntermediate(cert, csr) {
        let {
            commonName,
            altNames,
            ipSans,
            uriSans,
            otherSans,
            ttl,
            format,
            useCsrValues,
            maxPathLength,
            excludeCnFromSans,
            permittedDnsDomains,
            ou,
            organization,
            country,
            locality,
            province,
            streetAddress,
            postalCode
        } = cert.spec.signing;
        return this.vaultClient.write(`${cert.spec.root}/root/sign-intermediate`, {
            csr,
            common_name: commonName,
            alt_names: (altNames || []).join(','),
            ip_sans: (ipSans || []).join(','),
            uri_sans: (uriSans || []).join(','),
            other_sans: (otherSans || []).join(','),
            permitted_dns_domains: permittedDnsDomains,
            ttl,
            format,
            max_path_length: maxPathLength,
            exclude_cn_from_sans: excludeCnFromSans,
            use_csr_values: useCsrValues,
            ou,
            organization,
            country,
            locality,
            province,
            street_address: streetAddress,
            postal_code: postalCode
        })
    }

    generateRootCa(cert, generate) {
        let {
            type,
            commonName,
            altNames,
            ipSans,
            uriSans,
            otherSans,
            ttl,
            format,
            privateKeyFormat,
            keyType,
            keyBits,
            maxPathLength,
            excludeCnFromSans,
            permittedDnsDomains,
            ou,
            organization,
            country,
            locality,
            province,
            streetAddress,
            postalCode
        } = generate;
        return this.vaultClient.list(`${cert.spec.path}/certs`).then((certs) => {
            if (certs.data.keys.length === 0) {
                return this.vaultClient.write(`${cert.spec.path}/root/generate/${type}`, {
                    common_name: commonName,
                    alt_names: (altNames || []).join(','),
                    ip_sans: (ipSans || []).join(','),
                    uri_sans: (uriSans || []).join(','),
                    other_sans: (otherSans || []).join(','),
                    ttl,
                    format,
                    private_key_format: privateKeyFormat,
                    key_type: keyType,
                    key_bits: keyBits,
                    max_path_length: maxPathLength,
                    exclude_cn_from_sans: excludeCnFromSans,
                    permitted_dns_domains: permittedDnsDomains,
                    ou,
                    organization,
                    country,
                    locality,
                    province,
                    street_address: streetAddress,
                    postal_code: postalCode
                }).then((generated) => {
                    if (generated.data.certificate) {
                        console.log(`Certificate for ${commonName} generated`)
                    } else {
                        console.log(`Unable to generate certificate for ${commonName}`)
                    }
                })
            }
        })
    }

    generateIntermediateCa(cert, generate) {
        let {
            type,
            commonName,
            altNames,
            ipSans,
            uriSans,
            otherSans,
            format,
            privateKeyFormat,
            keyType,
            keyBits,
            excludeCnFromSans,
            ou,
            organization,
            country,
            locality,
            province,
            streetAddress,
            postalCode
        } = generate;
        return this.vaultClient.list(`${cert.spec.path}/certs`).then((certs) => {
            if (certs.data.keys.length === 0) {
                return this.vaultClient.write(`${cert.spec.path}/intermediate/generate/${type}`, {
                    common_name: commonName,
                    alt_names: (altNames || []).join(','),
                    ip_sans: (ipSans || []).join(','),
                    uri_sans: (uriSans || []).join(','),
                    other_sans: (otherSans || []).join(','),
                    format,
                    private_key_format: privateKeyFormat,
                    key_type: keyType,
                    key_bits: keyBits,
                    exclude_cn_from_sans: excludeCnFromSans,
                    ou,
                    organization,
                    country,
                    locality,
                    province,
                    street_address: streetAddress,
                    postal_code: postalCode
                })
            }
        })
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

    generateCertificate(cert, generate) {
        let {
            role,
            commonName,
            altNames,
            ipSans,
            uriSans,
            otherSans,
            ttl,
            format,
            privateKeyFormat,
            excludeCnFromSans
        } = generate;
        return this.vaultClient.write(`${cert.spec.path}/issue/${role}`, {
            common_name: commonName,
            alt_names: (altNames || []).join(','),
            ip_sans: (ipSans || []).join(','),
            uri_sans: (uriSans || []).join(','),
            other_sans: (otherSans || []).join(','),
            ttl,
            format,
            private_key_format: privateKeyFormat,
            exclude_cn_from_sans: excludeCnFromSans
        })
    }
}

module.exports = VaultHelper;