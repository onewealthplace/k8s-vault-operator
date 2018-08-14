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
}

module.exports = VaultHelper;