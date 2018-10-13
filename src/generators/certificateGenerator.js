const x509 = require('x509');

class CertificateGenerator {
    constructor(vaultClient) {
        this.vaultClient = vaultClient;
    }

    effectivelyGenerateCa(cert, onGenerated) {
        let {secretName, generate} = cert.spec;
        let namespace = cert.metadata.namespace || "default";
        return this.generateCertificate(cert, generate)
            .then((generated) => {
                let {certificate, issuing_ca, private_key, serial_number} = generated.data;
                if (certificate) {
                    console.log(`Certificate for ${namespace}/${cert.metadata.name} generated`);
                    return this.vaultClient.read(`${cert.spec.root}/ca/pem`).then((rootCa) => {
                        return this.recordSerial(cert.spec.path, namespace, cert.metadata.name, serial_number, generate.commonName, false)
                            .then(() => onGenerated(secretName, namespace, `${rootCa}\n${issuing_ca}`, certificate, private_key));
                    });
                } else {
                    console.log(`Unable to generate certificate for ${namespace}/${cert.metadata.name}`)
                }
            });
    }

    apply(cert, onGenerated) {
        let namespace = cert.metadata.namespace || "default";
        return this.vaultClient.read(`secret/data/serials/${cert.spec.path}/${namespace}/${cert.metadata.name}`)
            .then((serial) => {
                if (serial.data.data.revoked) {
                    return this.effectivelyGenerateCa(cert, onGenerated).then(() => this.linkCaToAuth(cert))
                }
            })
            .catch((err) => {
                console.log(err);
                if (err.response && err.response.statusCode === 404) {
                    return this.effectivelyGenerateCa(cert, onGenerated).then(() => this.linkCaToAuth(cert))
                }
            })
    }

    checkValidity(cert, onGenerated, onRevoked) {
        let namespace = cert.metadata.namespace || "default";
        return this.vaultClient.read(`secret/data/serials/${cert.spec.path}/${namespace}/${cert.metadata.name}`)
            .then((serial) => {
                if (serial.data.data.revoked) {
                    return this.effectivelyGenerateCa(cert, onGenerated).then(() => this.linkCaToAuth(cert))
                } else {
                    return this.vaultClient.read(`${cert.spec.path}/cert/${serial.data.data.serialNumber}`).then((certificate) => {
                        let parseCert = x509.parseCert(certificate.data.certificate);
                        if (parseCert.notAfter.getTime() < new Date().getTime()) {
                            console.log(`Found expired certificate for ${cert.metadata.name} in namespace ${namespace}`);
                            return this.revoke(cert, onRevoked).then(() => this.effectivelyGenerateCa(cert, onGenerated))
                        }
                    })
                }
            })
    }

    revoke(cert, onRevoked) {
        let namespace = cert.metadata.namespace || "default";
        let {secretName} = cert.spec;
        return this.vaultClient.read(`secret/data/serials/${cert.spec.path}/${namespace}/${cert.metadata.name}`).then((serial) => {
            if (serial.data.data.revoked) {
                console.log("Certificate already revoked")
            } else {
                return this.vaultClient.write(`${cert.spec.path}/revoke`, {serial_number: serial.data.data.serialNumber})
                    .then(() => this.recordSerial(cert.spec.path, namespace, cert.metadata.name, serial.data.data.serialNumber, serial.data.data.commonName, true))
                    .then(() => console.log(`Certificate ${namespace}/${cert.metadata.name} revoked`))
                    .then(() => this.unlinkCaToAuth(cert))
                    .then(() => onRevoked(secretName, namespace))
            }
        });
    }

    recordSerial(path, namespace, name, serialNumber, commonName, revoked) {
        return this.vaultClient.write(`secret/data/serials/${path}/${namespace}/${name}`, {data: {serialNumber, revoked, commonName}})
    }

    unlinkCaToAuth(cert) {
        let {
            accessorPath
        } = cert.spec.auth;
        let namespace = cert.metadata.namespace || "default";
        return this.vaultClient.delete(`auth/${accessorPath}/certs/${namespace}-${cert.metadata.name}`).then(() => console.log(`Certificate ${namespace}/${cert.metadata.name} unlinked`))
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