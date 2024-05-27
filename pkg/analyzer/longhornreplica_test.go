package analyzer

import (
	"os"
	"testing"

	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	lhv1beta1 "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta1"
	lhclient "github.com/longhorn/longhorn-manager/k8s/pkg/client/clientset/versioned"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
)

func TestApiDocs(t *testing.T) {
	assert := require.New(t)
	err := os.Setenv("KUBECONFIG", "/Users/gauravmehta/.kube/launch-event.yaml")
	assert.NoError(err)
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, nil)
	config, err := kubeConfig.ClientConfig()
	assert.NoError(err)
	utilruntime.Must(lhv1beta1.AddToScheme(scheme.Scheme))
	client, err := lhclient.NewForConfig(config)
	assert.NoError(err)
	lhOpenAPISchema, err := client.DiscoveryClient.OpenAPISchema()
	assert.NoError(err)
	apiDoc := kubernetes.K8sApiReference{
		Kind: "Ingress",
		ApiVersion: schema.GroupVersion{
			Group:   "networking",
			Version: "v1",
		},
		OpenapiSchema: lhOpenAPISchema,
	}

	doc := apiDoc.GetApiDocV2("spec.ingressClassName")
	t.Log(doc)
}
