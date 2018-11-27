
class SecretGenerator {
    constructor(vaultClient) {
        this.vaultClient = vaultClient;
    }

    apply(entity) {
        let {
            path,
            content
        } = entity.spec;

        return this.vaultClient.write(`secret/data/${path}`, {
            data: content
        }).then(() => console.log(`Secret ${entity.metadata.name} applied`));
    }

    delete(entity) {
        return this.vaultClient.delete(`secret/data/${entity.spec.path}`)
            .then(() => console.log(`Secret ${entity.metadata.name} deleted`));
    }
}

module.exports = SecretGenerator;