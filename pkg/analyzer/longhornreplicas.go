package analyzer

import (
	"context"
	"fmt"

	lhv1beta2 "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	lhclient "github.com/longhorn/longhorn-manager/k8s/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/kubectl/pkg/scheme"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
)

// LonghornAnalyzer is an analyzer that checks for longhorn specific objects
type LonghornAnalyzer struct{}

type lhAnalyzerFunction func(context.Context, *lhclient.Clientset, kubernetes.K8sApiReference) ([]common.Result, error)

var defaultLHAnalyzers = []lhAnalyzerFunction{volumeAnalyzer, replicaAnalyzer, nodeAnalyzer}

const (
	defaultLHNamespace = "longhorn-system"
)

// Analyze scans if any Longhorn rules are not met
func (l LonghornAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
	var currentAnalysis []common.Result
	utilruntime.Must(lhv1beta2.AddToScheme(scheme.Scheme))
	client, err := lhclient.NewForConfig(a.Client.Config)
	if err != nil {
		return nil, fmt.Errorf("error generating longhorn client: %v", err)
	}

	lhOpenAPISchema, err := client.DiscoveryClient.OpenAPISchema()
	if err != nil {
		return nil, err
	}

	apiDoc := kubernetes.K8sApiReference{
		ApiVersion: schema.GroupVersion{
			Group:   "longhorn.io",
			Version: "v1beta1",
		},
		OpenapiSchema: lhOpenAPISchema,
	}

	// check for possible replica issues
	for _, v := range defaultLHAnalyzers {
		results, err := v(a.Context, client, apiDoc)
		if err != nil {
			return nil, err
		}
		currentAnalysis = append(currentAnalysis, results...)
	}

	return currentAnalysis, nil
}

// replicaAnalyzer is expected to check if any LH replica is not in its desired state
func replicaAnalyzer(ctx context.Context, client *lhclient.Clientset, apiDoc kubernetes.K8sApiReference) ([]common.Result, error) {
	var currentAnalysis []common.Result
	kind := "Replica"
	apiDoc.Kind = kind
	AnalyzerErrorsMetric.DeletePartialMatch(map[string]string{
		"analyzer_name": kind,
	})
	doc := apiDoc.GetApiDocV2(".spec.desireState")

	// fetch replicas and check their state
	replicaList, err := client.LonghornV1beta2().Replicas(defaultLHNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing longhorn replicas: %v", err)
	}

	for _, replica := range replicaList.Items {
		var failures []common.Failure

		if replica.Spec.DesireState != replica.Status.CurrentState {
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("longhorn replica %s/%s has desired state %s but current state is %s", replica.Namespace, replica.Name, replica.Spec.DesireState, replica.Status.CurrentState),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{
						Unmasked: replica.Name,
						Masked:   util.MaskString(replica.Name),
					},
				},
			})
		}

		if len(failures) > 0 {
			currentAnalysis = append(currentAnalysis, common.Result{
				Kind:  "replica",
				Name:  fmt.Sprintf("%s/%s", replica.Namespace, replica.Name),
				Error: failures,
			})
		}

	}
	return currentAnalysis, nil
}

// volumeAnalyzer will check if the node is healthy
// if any replica is unhealthy we expect longhorn manager to mark this as unhealthy
func volumeAnalyzer(ctx context.Context, client *lhclient.Clientset, apiDoc kubernetes.K8sApiReference) ([]common.Result, error) {
	var currentAnalysis []common.Result
	kind := "Volume"
	apiDoc.Kind = kind
	AnalyzerErrorsMetric.DeletePartialMatch(map[string]string{
		"analyzer_name": kind,
	})
	doc := apiDoc.GetApiDocV2(".status.robustness")

	// fetch replicas and check their state
	volumeList, err := client.LonghornV1beta2().Volumes(defaultLHNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing longhorn volumes: %v", err)
	}

	for _, volume := range volumeList.Items {
		var failures []common.Failure
		if volume.Status.Robustness != lhv1beta2.VolumeRobustnessHealthy {
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("longhorn csi volume %s health is %s", volume.Name, volume.Status.Robustness),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{
						Unmasked: volume.Name,
						Masked:   util.MaskString(volume.Name),
					},
				},
			})
		}

		if len(failures) > 0 {
			currentAnalysis = append(currentAnalysis, common.Result{
				Kind:  "replica",
				Name:  fmt.Sprintf("%s/%s", volume.Namespace, volume.Name),
				Error: failures,
			})
		}

	}

	return currentAnalysis, nil
}

// nodeAnalyzer will check nodes.longhorn.io objects and perform the following checks
// identify if any disk is not schedulable
// identify if node is unschedulable when it is expected to be schedulable
func nodeAnalyzer(ctx context.Context, client *lhclient.Clientset, apiDoc kubernetes.K8sApiReference) ([]common.Result, error) {
	var currentAnalysis []common.Result
	kind := "Node"
	apiDoc.Kind = kind
	AnalyzerErrorsMetric.DeletePartialMatch(map[string]string{
		"analyzer_name": kind,
	})
	doc := apiDoc.GetApiDocV2(".status.robustness")

	nodeList, err := client.LonghornV1beta2().Nodes(defaultLHNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing longhorn nodes: %v", err)
	}

	for _, node := range nodeList.Items {
		var failures []common.Failure
		var nodeSchedulableStatus bool
		for diskName, diskStatus := range node.Status.DiskStatus {
			for _, condition := range diskStatus.Conditions {
				if condition.Type == lhv1beta2.DiskConditionTypeReady {
					if condition.Status == lhv1beta2.ConditionStatusTrue {
						nodeSchedulableStatus = nodeSchedulableStatus || true
					} else {
						// since disk is not schedulable lets report a failure
						// to ensure user can check
						failures = append(failures, common.Failure{
							Text:          fmt.Sprintf("longhorn disk %s on node %s current status is not ready", diskName, node.Name),
							KubernetesDoc: doc,
							Sensitive: []common.Sensitive{
								{
									Unmasked: diskName,
									Masked:   util.MaskString(diskName),
								},
							},
						})
					}
				}
			}
		}
		// check if nodeSchedulableStatus is true
		// even a single schedulable disk would ensure node is schedulable
		// if node is supposed to be schedulable but is not then generate another failure
		if node.Spec.AllowScheduling && !nodeSchedulableStatus {
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("longhorn node %s is expected to be schedulable but is not schedulable", node.Name),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{
						Unmasked: node.Name,
						Masked:   util.MaskString(node.Name),
					},
				},
			})
		}

		if len(failures) > 0 {
			currentAnalysis = append(currentAnalysis, common.Result{
				Kind:  "node",
				Name:  fmt.Sprintf("%s/%s", node.Namespace, node.Name),
				Error: failures,
			})
		}
	}
	return currentAnalysis, nil
}
