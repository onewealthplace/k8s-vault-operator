class CertificateGenerator {
    constructor(vaultClient) {
        this.vaultClient = vaultClient;
    }

    apply(cert, onGenerated) {
        let {secretName, generate} = cert.spec;
        let namespace = cert.metadata.namespace || "default";
        let effectivelyGenerateCa = () => this.generateCertificate(cert, generate)
            .then((generated) => {
                let {certificate, issuing_ca, private_key, serial_number} = generated.data;
                if (certificate) {
                    console.log(`Certificate for ${namespace}/${cert.metadata.name} generated`);
                    return this.recordSerial(cert.spec.path, namespace, cert.metadata.name, serial_number, generate.commonName, false)
                        .then(() => onGenerated(secretName, namespace, issuing_ca, certificate, private_key));
                } else {
                    console.log(`Unable to generate certificate for ${namespace}/${cert.metadata.name}`)
                }
            });
        return this.vaultClient.read(`secret/data/serials/${cert.spec.path}/${namespace}/${cert.metadata.name}`)
            .then((serial) => {
                if (serial.data.data.revoked) {
                    return effectivelyGenerateCa()
                }
            })
            .catch(() => effectivelyGenerateCa())
            .then(() => this.linkCaToAuth(cert))
    }

    revoke(cert) {
        let namespace = cert.metadata.namespace || "default";
        return this.vaultClient.read(`secret/data/serials/${cert.spec.path}/${namespace}/${cert.metadata.name}`).then((serial) => {
            if (serial.data.data.revoked) {
                console.log("Certificate already revoked")
            } else {
                return this.vaultClient.write(`${cert.spec.path}/revoke`, {serial_number: serial.data.data.serialNumber})
                    .then(() => this.recordSerial(cert.spec.path, namespace, cert.metadata.name, serial.data.data.serialNumber, serial.data.data.commonName, true))
                    .then(() => console.log(`Certificate ${namespace}/${cert.metadata.name} revoked`))
            }
        });
    }

    recordSerial(path, namespace, name, serialNumber, commonName, revoked) {
        return this.vaultClient.write(`secret/data/serials/${path}/${namespace}/${name}`, {data: {serialNumber, revoked, commonName}})
    }

    linkCaToAuth(cert) {
        if (!cert.spec.auth) return Promise.resolve();
        let {
            accessorPath,
            allowedCommonNames,
            allowedDnsSans,
            allowedEmailSans,
            allowedUriSans,
            requiredExtensions,
            maxTtl,
            ttl,
            policies,
            period,
            boundCidrs,
            displayName
        } = cert.spec.auth;
        let namespace = cert.metadata.namespace || "default";
        return this.vaultClient.read(`secret/data/serials/${cert.spec.path}/${namespace}/${cert.metadata.name}`)
            .then((serial) => {
                if (!serial.data.data.revoked) {
                    return this.vaultClient.read(`${cert.spec.path}/cert/${serial.data.data.serialNumber}`).then((certificate) => {
                        let writeCert = () => this.vaultClient.write(`auth/${accessorPath}/certs/${namespace}-${cert.metadata.name}`, {
                            certificate: certificate.data.certificate,
                            allowed_common_names: allowedCommonNames,
                            allowed_dns_sans: allowedDnsSans,
                            allowed_email_sans: allowedEmailSans,
                            allowed_uri_sans: allowedUriSans,
                            required_extensions: requiredExtensions,
                            policies,
                            display_name: displayName,
                            ttl,
                            max_ttl: maxTtl,
                            period,
                            bound_cidrs: boundCidrs
                        });
                        return this.vaultClient.list(`auth/${accessorPath}/certs`).then((certs) => {
                            if (certs.data.keys.indexOf(`${namespace}-${cert.metadata.name}`) > -1) return Promise.resolve();
                            return writeCert()
                        }).catch(() => writeCert());
                    })
                }
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

module.exports = CertificateGenerator;