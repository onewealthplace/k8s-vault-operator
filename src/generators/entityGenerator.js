
class EntityGenerator {
    constructor(vaultClient) {
        this.vaultClient = vaultClient;
    }

    apply(entity) {
        let {
            name,
            metadata,
            policies,
            aliases
        } = entity.spec;

        return this.vaultClient.write('identity/entity', {
            name,
            metadata,
            policies
        })
            .then(() => this.applyAliases(name, aliases))
            .catch((err) => {
                if (err.response && err.response.statusCode === 404) {
                    return this.applyAliases(name, aliases)
                }
            });
    }

    applyAliases(name, aliases) {
        return this.vaultClient.write('identity/lookup/entity', {name}).then((entity) => {
            return Promise.all(aliases.filter((a) =>
                entity.data.aliases.find(aa => aa.name === a.name) === undefined
            ).map((alias) => {
                let {name, metadata, accessorPath} = alias;
                return this.vaultClient.read(`sys/auth`).then((auths) => {
                    let accessor = auths.data[`${accessorPath}/`].accessor;
                    return this.vaultClient.write('identity/entity-alias', {
                        name, metadata, canonical_id: entity.data.id, mount_accessor: accessor
                    })
                });
            }))
        });
    }

    delete(entity) {
        return this.vaultClient.write('identity/lookup/entity', {name: entity.spec.name}).then((entity) => {
            return this.vaultClient.delete(`identity/entity/id/${entity.data.id}`)
        }).then(() => console.log(`Entity ${entity.spec.name} deleted`));
    }
}

module.exports = EntityGenerator;