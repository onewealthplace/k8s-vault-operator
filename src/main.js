const VaultHelper = require("./vaultHelper");
const K8SHelper = require("./k8sHelper");
const vaultPolicyCrd = require('./crds/vaultPolicy.crd.json');
const vaultCertificateCrd = require("./crds/vaultCertificate.crd.json");
const vaultSecretEngineCrd = require("./crds/vaultSecretEngine.crd.json");
const vaultAuthEngineCrd = require("./crds/vaultAuthEngine.crd.json");
const vaultRootCertificateCrd = require("./crds/vaultRootCertificate.crd.json");
const vaultIntermediateCertificateCrd = require("./crds/vaultIntermediateCertificate.crd.json");
const vaultEntityCrd = require("./crds/vaultEntity.crd");

async function main() {
    try {
        if (!process.env.VAULT_TOKEN || !process.env.VAULT_HOST || !process.env.VAULT_PORT || !process.env.VAULT_TLS_CA) {
            console.error("Please check that VAULT_HOST & VAULT_PORT & VAULT_TOKEN & VAULT_TLS_CA env vars are set correctly");
            process.exit(1);
        }
        const kubernetesHelper = new K8SHelper();
        const vaultHelper = new VaultHelper();

        await kubernetesHelper.createCrd(vaultPolicyCrd);
        await kubernetesHelper.createCrd(vaultCertificateCrd);
        await kubernetesHelper.createCrd(vaultSecretEngineCrd);
        await kubernetesHelper.createCrd(vaultAuthEngineCrd);
        await kubernetesHelper.createCrd(vaultRootCertificateCrd);
        await kubernetesHelper.createCrd(vaultIntermediateCertificateCrd);
        await kubernetesHelper.createCrd(vaultEntityCrd);

        const onCaGenerated = (secretName, namespace, caChain, certificate, privateKey) => {
            if (certificate) {
                return kubernetesHelper.applySecret(secretName, namespace, {
                    "ca.pem": caChain,
                    "cert.pem": certificate,
                    "key.pem": privateKey
                });
            }
        };

        kubernetesHelper.watchCRD(vaultPolicyCrd,
            (obj) => vaultHelper.applyPolicy(obj),
            (obj) => vaultHelper.applyPolicy(obj),
            (obj) => vaultHelper.deletePolicy(obj)
        );

        kubernetesHelper.watchCRD(vaultAuthEngineCrd,
            (obj) => vaultHelper.applyAuthEngine(obj),
            (obj) => vaultHelper.applyAuthEngine(obj),
            (obj) => vaultHelper.disableAuthEngine(obj)
        );

        kubernetesHelper.watchCRD(vaultSecretEngineCrd,
            (obj) => vaultHelper.applySecretEngine(obj),
            () => console.log("Update of Secret Engine forbidden"),
            () => console.log("Delete of Secret Engine forbidden")
        );

        kubernetesHelper.watchCRD(vaultEntityCrd,
            (obj) => vaultHelper.applyEntity(obj),
            (obj) => vaultHelper.applyEntity(obj),
            (obj) => vaultHelper.deleteEntity(obj),
        );

        kubernetesHelper.watchCRD(vaultCertificateCrd,
            (obj) => vaultHelper.applyCa(obj, onCaGenerated),
            (obj) => vaultHelper.applyCa(obj, onCaGenerated),
            (obj) => vaultHelper.revokeCa(obj)
        );

        kubernetesHelper.watchCRD(vaultRootCertificateCrd,
            (obj) => vaultHelper.applyRootCa(obj),
            () => console.log("Update of Root certificates forbidden"),
            () => console.log("Delete of Root certificates forbidden")
        );

        kubernetesHelper.watchCRD(vaultIntermediateCertificateCrd,
            (obj) => vaultHelper.applyIntermediateCa(obj).then(() => vaultHelper.applyRoles(obj)),
            (obj) => vaultHelper.applyRoles(obj),
            () => console.log("Delete of Intermediate certificates forbidden")
        );

    } catch (err) {
        console.error('Error: ', err);
    }
}

main();