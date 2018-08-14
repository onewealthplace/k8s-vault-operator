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
            await apiExtensions.crd(crd.metadata.name).get();
            console.log(`Found definition for ${crd.metadata.name}`)
        } catch (_) {
            await apiExtensions.customresourcedefinitions.post({body: crd});
            console.log(`Create: ${crd.metadata.name}`);
        }
        this.kubernetesClient.addCustomResourceDefinition(crd);
    }
}

module.exports = KubernetesHelper;