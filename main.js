const VaultHelper = require("./vaultHelper");
const K8SHelper = require("./k8sHelper");
const crd = require('./vaultPolicy.crd.json');

async function main() {
    try {
        if (!process.env.VAULT_TOKEN || !process.env.VAULT_HOST || !process.env.VAULT_PORT || !process.env.VAULT_TLS_CA) {
            console.error("Please check that VAULT_HOST & VAULT_PORT & VAULT_TOKEN & VAULT_TLS_CA env vars are set correctly");
            process.exit(1);
        }
        const kubernetesHelper = new K8SHelper();
        const vaultHelper = new VaultHelper();

        await kubernetesHelper.createCRDs(crd);

        kubernetesHelper.watchCRD(
            'vault.operators.onewealthplace.com',
            'vaultpolicies',
            (obj) => vaultHelper.applyPolicy(obj),
            (obj) => vaultHelper.applyPolicy(obj),
            (obj) => vaultHelper.deletePolicy(obj)
        );

    } catch (err) {
        console.error('Error: ', err);
    }
}

main();