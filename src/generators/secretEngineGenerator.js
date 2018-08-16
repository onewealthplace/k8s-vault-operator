class SecretEngineGenerator {
    constructor(vaultClient) {
        this.vaultClient = vaultClient;
    }

    apply(secretEngine) {
        let {
            path,
            type,
            description,
            config,
            options,
            local,
            sealWrap
        } = secretEngine.spec;
        let {
            defaultLeaseTtl,
            maxLeaseTtl,
            forceNoCache,
            pluginName,
            auditNonHmacRequestKeys,
            auditNonHmacResponseKeys,
            listingVisibility,
            passthroughRequestHeaders
        } = config;
        return this.vaultClient.mounts().then((mounts) => {
            if (!mounts[`${path}/`]) {
                return this.vaultClient.mount({
                    mount_point: path,
                    type,
                    description,
                    config: {
                        default_lease_ttl: defaultLeaseTtl,
                        max_lease_ttl: maxLeaseTtl,
                        force_no_cache: forceNoCache,
                        plugin_name: pluginName,
                        audit_non_hmac_request_keys: (auditNonHmacRequestKeys || []).concat(','),
                        audit_non_hmac_response_keys: (auditNonHmacResponseKeys || []).concat(','),
                        listing_visibility: listingVisibility,
                        passthrough_request_headers: (passthroughRequestHeaders || []).concat(',')
                    },
                    options,
                    plugin_name: secretEngine.spec.pluginName,
                    local,
                    seal_wrap: sealWrap
                })
            }
        });
    }

}

module.exports = SecretEngineGenerator;