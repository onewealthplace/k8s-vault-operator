
class RootCaGenerator {
    constructor(vaultClient) {
        this.vaultClient = vaultClient;
    }

    apply(resource, fetchSecret) {
        let {pemBundle, generate} = resource.spec;
        return this.vaultClient.read(`${resource.spec.path}/cert/ca`).catch((err) => {
            if (err.response && err.response.statusCode === 404) {
                if (pemBundle) {
                    return fetchSecret(resource.metadata.namespace || "default", pemBundle.secretRef.name).then(({certificate, key}) => {
                        return this.vaultClient.write(`${resource.spec.path}/config/ca`, {
                            pem_bundle: `${key}\n${certificate}`
                        });
                    });
                } else if (generate) {
                    return this.generateRootCa(resource, generate)
                }
            }
        });
    }

    generateRootCa(resource, generate) {
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
        return this.vaultClient.write(`${resource.spec.path}/root/generate/${type}`, {
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
            if (generated.data && generated.data.certificate) {
                console.log(`Certificate for ${commonName} generated`);
                return generated.data.certificate
            } else {
                throw new Error(`Unable to generate certificate for ${commonName}`)
            }
        })
    }

}

module.exports = RootCaGenerator;