class IntermediateCaGenerator {
    constructor(vaultClient) {
        this.vaultClient = vaultClient;
    }

    apply(cert) {
        let {certificate, generate} = cert.spec;
        return this.vaultClient.list(`${cert.spec.path}/certs`).catch(() => {
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
        });
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
}

module.exports = IntermediateCaGenerator;