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


    watchCRD(group, kind, onCreate, onUpdate, onDelete) {
        const stream = this.kubernetesClient.apis[group].v1.watch[kind].getStream();
        const jsonStream = new JSONStream();
        stream.pipe(jsonStream);

        jsonStream.on('data', async event => {
            const id = `${ event.object.metadata.namespace }/${ event.object.metadata.name }`;
            if (event.type === 'ADDED') {
                await onCreate(event.object);
                console.log(`${group}.${kind} ${id} added`);
            } else if (event.type === 'DELETED') {
                await onDelete(event.object);
                console.log(`${group}.${kind} ${id} deleted`);
            } else if (event.type === 'MODIFIED') {
                await onUpdate(event.object);
                console.log(`${group}.${kind} ${id} updated`);
            }
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
            this.kubernetesClient.api.v1.namespaces(namespace).secrets.post(payload)
        }catch (err) {
            if (err.code !== 409) throw err;
            this.kubernetesClient.api.v1.namespaces(namespace).secrets(name).put(payload)
        }
    }
}

module.exports = KubernetesHelper;