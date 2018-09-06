const VaultClient = require("node-vault");
const fs = require('fs');
const RootCaGenerator = require("./generators/rootCaGenerator");
const CertificateGenerator = require("./generators/certificateGenerator");
const IntermediateCaGenerator = require("./generators/intermediateCaGenerator");
const RoleGenerator = require("./generators/roleGenerator");
const EntityGenerator = require("./generators/entityGenerator");
const PolicyGenerator = require("./generators/policyGenerator");
const SecretEngineGenerator = require("./generators/secretEngineGenerator");
const AuthEngineGenerator = require("./generators/authEngineGenerator");

class VaultHelper {
    constructor() {
        this.vaultClient = VaultClient({
            apiVersion: 'v1',
            endpoint: `https://${process.env.VAULT_HOST}:${process.env.VAULT_PORT}`,
            token: process.env.VAULT_TOKEN,
            requestOptions: {
                ca: fs.readFileSync(process.env.VAULT_TLS_CA),
            }
        });
        const rootCaGenerator = new RootCaGenerator(this.vaultClient);
        const certificateGenerator = new CertificateGenerator(this.vaultClient);
        const intermediateCaGenerator = new IntermediateCaGenerator(this.vaultClient);
        const roleGenerator = new RoleGenerator(this.vaultClient);
        const entityGenerator = new EntityGenerator(this.vaultClient);
        const policyGenerator = new PolicyGenerator(this.vaultClient);
        const secretEngineGenerator = new SecretEngineGenerator(this.vaultClient);
        const authEngineGenerator = new AuthEngineGenerator(this.vaultClient);

        this.applyRootCa = (r, fetchSecret) => rootCaGenerator.apply(r, fetchSecret);
        this.applyIntermediateCa = (r) => intermediateCaGenerator.apply(r);
        this.applyCa = (r, cb) => certificateGenerator.apply(r, cb);
        this.applyRoles = (r) => roleGenerator.apply(r);
        this.applyPolicy = (r) => policyGenerator.apply(r);
        this.applyAuthEngine = (r) => authEngineGenerator.apply(r);
        this.applySecretEngine = (r) => secretEngineGenerator.apply(r);
        this.applyEntity = (r) => entityGenerator.apply(r);
        this.revokeCa = (r, cb) => certificateGenerator.revoke(r, cb);
        this.disableAuthEngine = (r) => authEngineGenerator.disable(r);
        this.deletePolicy = (r) => policyGenerator.delete(r);
        this.deleteEntity = (r) => entityGenerator.delete(r);
    }
}

module.exports = VaultHelper;