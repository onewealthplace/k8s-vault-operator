const K8SClient = require('kubernetes-client').Client;
const config = require('kubernetes-client').config;
const JSONStream = require('json-stream');

class KubernetesHelper {

    constructor() {
        this.kubernetesClient = new K8SClient({
            config: process.env.KUBERNETES_SERVICE_HOST ? config.getInCluster() : config.fromKubeconfig(),
            version: '1.10'
        })
    }


    watchCRD(crd, onCreate, onUpdate, onDelete) {
        const group = crd.spec.group;
        const kind = crd.spec.names.plural;
        const stream = this.kubernetesClient.apis[group].v1.watch[kind].getStream();
        const jsonStream = new JSONStream();
        stream.pipe(jsonStream);

        console.log(`Watch on ${group}.${kind}`);
        jsonStream.on('data', async event => {
            try {
                if (event.type === 'ADDED') {
                    await onCreate(event.object);
                } else if (event.type === 'DELETED') {
                    await onDelete(event.object);
                } else if (event.type === 'MODIFIED') {
                    await onUpdate(event.object);
                }
            } catch (err) {
                console.error(`Error while processing ${event.object.metadata.namespace}/${event.object.metadata.name}`, err)
            }
        });
        jsonStream.on('end', () => {
            this.watchCRD(crd, onCreate, onUpdate, onDelete)
        });
        jsonStream.on('error', () => {
            this.watchCRD(crd, onCreate, onUpdate, onDelete)
        });
    }

    async createCrd(crd) {
//
        // Create the CRD with the Kubernetes API
        //
        let apiExtensions = this.kubernetesClient.apis['apiextensions.k8s.io'].v1beta1;
        try {
            await apiExtensions.customresourcedefinitions.post({body: crd});
            console.log(`Create: ${crd.metadata.name}`)
        } catch (err) {
            if (err.code !== 409) throw err;
            console.log(`Resource already exist: ${crd.metadata.name}`);
        }
        this.kubernetesClient.addCustomResourceDefinition(crd);
    }

    async applySecret(name, namespace, content) {
        let data = {};
        Object.keys(content).forEach((key) => {
            data[key] = Buffer.from(content[key]).toString('base64')
        });
        let payload = {body: {
                apiVersion: "v1",
                kind: "Secret",
                metadata: {
                    name,
                    namespace
                },
                data
            }};
        try {
            return await this.kubernetesClient.api.v1.namespaces(namespace).secrets.post(payload).then(() => console.log(`Secret ${namespace}/${name} created`))
        } catch (_) {
            return await this.kubernetesClient.api.v1.namespaces(namespace).secrets(name).patch(payload).then(() => console.log(`Secret ${namespace}/${name} patched`))
        }
    }

    async deleteSecret(name, namespace) {
        return await this.kubernetesClient.api.v1.namespaces(namespace).secrets(name).delete().then(() => console.log(`Secret ${namespace}/${name} deleted`))
    }

    async getSecret(namespace, name) {
        return await this.kubernetesClient.api.v1.namespaces(namespace).secrets(name).get();
    }
}

module.exports = KubernetesHelper;