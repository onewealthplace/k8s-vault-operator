
class PolicyGenerator {
    constructor(vaultClient) {
        this.vaultClient = vaultClient;
    }

    apply(policy) {
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

    delete(policy) {
        let {name} = policy.spec;
        return this.vaultClient.removePolicy({name}).then(() => console.log(`Policy ${name} deleted`))
    }

}

module.exports = PolicyGenerator;