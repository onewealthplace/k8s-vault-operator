
class AuthEngineGenerator {
    constructor(vaultClient) {
        this.vaultClient = vaultClient;
    }

    apply(authEngine) {
        let {
            path,
            type,
            description,
            config,
            options,
            local
        } = authEngine.spec;
        let {
            defaultLeaseTtl,
            maxLeaseTtl,
            pluginName,
            auditNonHmacRequestKeys,
            auditNonHmacResponseKeys,
            listingVisibility,
            passthroughRequestHeaders
        } = config || {};
        return this.vaultClient.auths().then((auths) => {
            if (!auths[`${path}/`]) {
                return this.vaultClient.enableAuth({
                    mount_point: path,
                    type,
                    description,
                    config: {
                        default_lease_ttl: defaultLeaseTtl,
                        max_lease_ttl: maxLeaseTtl,
                        plugin_name: pluginName,
                        audit_non_hmac_request_keys: (auditNonHmacRequestKeys || []).concat(','),
                        audit_non_hmac_response_keys: (auditNonHmacResponseKeys || []).concat(','),
                        listing_visibility: listingVisibility,
                        passthrough_request_headers: (passthroughRequestHeaders || []).concat(',')
                    },
                    options,
                    plugin_name: authEngine.spec.pluginName,
                    local
                })
            }
        });
    }

    disable(authEngine) {
        return this.vaultClient.disableAuth({
            mount_point: authEngine.spec.path
        }).then(() => console.log(`Auth engine ${authEngine.spec.path} disabled`))
    }

}

module.exports = AuthEngineGenerator;