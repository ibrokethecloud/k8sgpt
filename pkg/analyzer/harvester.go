package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	ncv1beta "github.com/harvester/harvester-network-controller/pkg/apis/network.harvesterhci.io/v1beta1"
	ncClient "github.com/harvester/harvester-network-controller/pkg/generated/clientset/versioned"
	hvV1beta1 "github.com/harvester/harvester/pkg/apis/harvesterhci.io/v1beta1"
	hvClient "github.com/harvester/harvester/pkg/generated/clientset/versioned"
	"github.com/harvester/pcidevices/pkg/apis/devices.harvesterhci.io/v1beta1"
	pcidevices "github.com/harvester/pcidevices/pkg/generated/clientset/versioned"
	"github.com/harvester/pcidevices/pkg/util/gpuhelper"
	"github.com/rancher/rancher/pkg/generated/controllers/fleet.cattle.io"
	corev1 "k8s.io/api/core/v1"
	apiextensionClient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	kubeAggregatorClient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	"k8s.io/kubectl/pkg/scheme"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
)

const (
	harvesterRouteAnnotation      = "network.harvesterhci.io/route"
	harvesterRouteConnectivityKey = "connectivity"
	defaultHarvesterNamespace     = "harvester-system"
	harvesterUpgradeSuccessStatus = "Succeeded"
	harvesterUpgradeStateKey      = "harvesterhci.io/upgradeState"
	defaultDelayDuration          = 2 * time.Hour
	defaultFleetNamespace         = "fleet-local"
	pciDeviceCRDName              = "pcidevices.devices.harvesterhci.io"
	vgpuDeviceCRDName             = "vgpudevices.devices.harvesterhci.io"
)

// HarvesterAnalyzer is an analyzer that checks for harvester specific objects
type HarvesterAnalyzer struct {
	hvClient         *hvClient.Clientset
	ncClient         *ncClient.Clientset
	client           *kubernetes.Client
	aggregatorClient *kubeAggregatorClient.Clientset
	fleetClient      fleet.Interface
	pciClient        *pcidevices.Clientset
	apiClient        *apiextensionClient.Clientset
}

type analyzerFunction func(context.Context, kubernetes.K8sApiReference) ([]common.Result, error)

// Analyze scans if any harvester rules are not met
func (h HarvesterAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
	var currentAnalysis []common.Result
	utilruntime.Must(hvV1beta1.AddToScheme(scheme.Scheme))
	hvc, err := hvClient.NewForConfig(a.Client.Config)
	if err != nil {
		return nil, fmt.Errorf("error generating harvester client: %v", err)
	}
	nwc, err := ncClient.NewForConfig(a.Client.Config)
	if err != nil {
		return nil, fmt.Errorf("error generating network controller client: %v", err)
	}

	harvOpenAPISchema, err := hvc.Discovery().OpenAPISchema()
	if err != nil {
		return nil, err
	}

	// fleet does not have an official clientset package so no need to leverage k8sapi reference
	// since we are just re-using the one from harvester for now

	fleetFactory, err := fleet.NewFactoryFromConfig(a.Client.Config)
	if err != nil {
		return nil, fmt.Errorf("error initialisting fleet client factory: %v", err)
	}

	aggregatorClient, err := kubeAggregatorClient.NewForConfig(a.Client.Config)
	if err != nil {
		return nil, fmt.Errorf("error generating aggregator client: %v", err)
	}

	pciClient, err := pcidevices.NewForConfig(a.Client.Config)
	if err != nil {
		return nil, fmt.Errorf("error generating pci client: %v", err)
	}
	apiClient, err := apiextensionClient.NewForConfig(a.Client.Config)
	if err != nil {
		return nil, fmt.Errorf("error generating api client: %v", err)
	}

	h.hvClient = hvc
	h.ncClient = nwc
	h.client = a.Client
	h.fleetClient = fleetFactory.Fleet()
	h.aggregatorClient = aggregatorClient
	h.pciClient = pciClient
	h.apiClient = apiClient

	hvApiDoc := kubernetes.K8sApiReference{
		ApiVersion: schema.GroupVersion{
			Group:   "harvesterhci.io",
			Version: "v1beta1",
		},
		OpenapiSchema: harvOpenAPISchema,
	}

	defaultHarvesterAnalyzers := []analyzerFunction{h.clusterNetworkAnalyzer, h.machineAnalyzer, h.checkFailedUpgrades, h.checkFleetBundles}
	for _, v := range defaultHarvesterAnalyzers {
		results, err := v(a.Context, hvApiDoc)
		if err != nil {
			return nil, err
		}
		currentAnalysis = append(currentAnalysis, results...)
	}

	ncOpenaAPISchema, err := nwc.Discovery().OpenAPISchema()
	if err != nil {
		return nil, err
	}
	ncApiDoc := kubernetes.K8sApiReference{
		ApiVersion: schema.GroupVersion{
			Group:   "network.harvesterhci.io",
			Version: "v1beta1",
		},
		OpenapiSchema: ncOpenaAPISchema,
	}

	// network analysis
	defaultNetworkAnanlyzers := []analyzerFunction{h.nadAnalyzer}
	for _, v := range defaultNetworkAnanlyzers {
		results, err := v(a.Context, ncApiDoc)
		if err != nil {
			return nil, err
		}
		currentAnalysis = append(currentAnalysis, results...)
	}

	// apiregistration analysis
	apiRegSchema, err := apiClient.Discovery().OpenAPISchema()
	if err != nil {
		return nil, err
	}
	apiRegDoc := kubernetes.K8sApiReference{
		ApiVersion: schema.GroupVersion{
			Group:   "apiregistration.k8s.io",
			Version: "v1",
		},
		OpenapiSchema: apiRegSchema,
	}

	aggregatorAnalyzers := []analyzerFunction{h.checkAPIServices}
	for _, v := range aggregatorAnalyzers {
		results, err := v(a.Context, apiRegDoc)
		if err != nil {
			return nil, err
		}
		currentAnalysis = append(currentAnalysis, results...)
	}

	// pcidevices analysis
	coreSchema, err := a.Client.Client.Discovery().OpenAPISchema()
	if err != nil {
		return nil, err
	}
	coreRegDoc := kubernetes.K8sApiReference{
		ApiVersion: schema.GroupVersion{
			Group:   "",
			Version: "v1",
		},
		OpenapiSchema: coreSchema,
	}

	deviceAnalyzers := []analyzerFunction{h.checkPCIDeviceClaims, h.checkVGPUDevices}
	for _, v := range deviceAnalyzers {
		results, err := v(a.Context, coreRegDoc)
		if err != nil {
			return nil, err
		}
		currentAnalysis = append(currentAnalysis, results...)
	}
	return currentAnalysis, nil

}

func (h HarvesterAnalyzer) nadAnalyzer(ctx context.Context, _ kubernetes.K8sApiReference) ([]common.Result, error) {
	var currentAnalysis []common.Result

	nadList, err := h.hvClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, nad := range nadList.Items {
		var failures []common.Failure
		val, ok := nad.Annotations[harvesterRouteAnnotation]
		if !ok {
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("multus network-attachment-definition %s/%s has not route annotation defined", nad.Namespace, nad.Name),
				KubernetesDoc: "",
				Sensitive: []common.Sensitive{
					{
						Unmasked: nad.Name,
						Masked:   util.MaskString(nad.Name),
					},
				},
			})
		} else {
			// check if route is ready
			annotationDetails := make(map[string]string)
			if err := json.Unmarshal([]byte(val), &annotationDetails); err != nil {
				return nil, err
			}
			if annotationDetails[harvesterRouteConnectivityKey] != "true" {
				failures = append(failures, common.Failure{
					Text:          fmt.Sprintf("multus network-attachment-definition %s/%s has connectivity failure %s", nad.Namespace, nad.Name, annotationDetails[harvesterRouteConnectivityKey]),
					KubernetesDoc: "",
					Sensitive: []common.Sensitive{
						{
							Unmasked: nad.Name,
							Masked:   util.MaskString(nad.Name),
						},
					},
				})
			}
		}
		if len(failures) > 0 {
			currentAnalysis = append(currentAnalysis, common.Result{
				Kind:  "NetworkAttachmentDefinition",
				Name:  fmt.Sprintf("%s/%s", nad.Namespace, nad.Name),
				Error: failures,
			})
		}
	}
	return currentAnalysis, nil
}

func (h HarvesterAnalyzer) clusterNetworkAnalyzer(ctx context.Context, _ kubernetes.K8sApiReference) ([]common.Result, error) {
	var currentAnalysis []common.Result
	clusterNetworkList, err := h.ncClient.NetworkV1beta1().ClusterNetworks().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, clusterNetwork := range clusterNetworkList.Items {
		var ready bool
		var failures []common.Failure
		for _, condition := range clusterNetwork.Status.Conditions {
			if condition.Type == ncv1beta.Ready && condition.Status == corev1.ConditionTrue {
				ready = true
			}
		}

		if !ready {
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("harvester cluster network %s is not ready", clusterNetwork.Name),
				KubernetesDoc: "",
				Sensitive: []common.Sensitive{
					{
						Unmasked: clusterNetwork.Name,
						Masked:   util.MaskString(clusterNetwork.Name),
					},
				},
			})
			currentAnalysis = append(currentAnalysis, common.Result{
				Kind:  "ClusterNetwork",
				Name:  clusterNetwork.Name,
				Error: failures,
			})
		}
	}
	return currentAnalysis, nil
}

// reconcile if k8s node and equivalent machine crd exists
// also find extra machine crds and verify their status
func (h HarvesterAnalyzer) machineAnalyzer(ctx context.Context, apiDoc kubernetes.K8sApiReference) ([]common.Result, error) {
	var currentAnalysis []common.Result
	machineList, err := h.hvClient.ClusterV1alpha4().Machines("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	kind := "Machine"
	apiDoc.Kind = kind
	AnalyzerErrorsMetric.DeletePartialMatch(map[string]string{
		"analyzer_name": kind,
	})
	doc := apiDoc.GetApiDocV2(".status.nodeRef.name")

	for _, machine := range machineList.Items {
		var failures []common.Failure
		var machineNotFound bool
		node, err := h.client.Client.CoreV1().Nodes().Get(ctx, machine.Status.NodeRef.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				machineNotFound = true
			} else {
				return nil, err
			}
		}

		// if node has been deleted, it is possible that the machine crd is left behind which may affect upgrades
		if machineNotFound {
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("k8s node %s corresponding to machine %s does not exist", machine.Status.NodeRef.Name, machine.Name),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{
						Unmasked: machine.Name,
						Masked:   util.MaskString(machine.Name),
					},
				},
			})
		} else {
			// if machine and node object timestamps are different, there it will catch an edge case
			// where the machine may have been recreated
			// in normal conditions, when a node is added, the associated machine crd registers within seconds
			// however in cases where there is a likely issue, then it is something user should investigate
			nodeTime := node.GetCreationTimestamp()
			machineTime := machine.GetCreationTimestamp()

			if nodeTime.Add(defaultDelayDuration).Before(machineTime.Add(0 * time.Second)) {
				failures = append(failures, common.Failure{
					Text:          fmt.Sprintf("k8s node %s and machine %s registration timestamp variance high, likely a re-registration of machine", node.Name, machine.Name),
					KubernetesDoc: doc,
					Sensitive: []common.Sensitive{
						{
							Unmasked: machine.Name,
							Masked:   util.MaskString(machine.Name),
						},
					},
				})
			}
		}

		if len(failures) > 0 {
			currentAnalysis = append(currentAnalysis, common.Result{
				Kind:  kind,
				Name:  machine.Name,
				Error: failures,
			})
		}
	}
	return currentAnalysis, nil
}

// reconcile fleet bundles and ensure they are not modified or out of sync

// reconcile upgrades.harvester CRD and ensure there are not failed upgrades present in the history
func (h HarvesterAnalyzer) checkFailedUpgrades(ctx context.Context, apiDoc kubernetes.K8sApiReference) ([]common.Result, error) {
	var currentAnalysis []common.Result
	upgrades, err := h.hvClient.HarvesterhciV1beta1().Upgrades(defaultHarvesterNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	kind := "Upgrade"
	apiDoc.Kind = kind
	AnalyzerErrorsMetric.DeletePartialMatch(map[string]string{
		"analyzer_name": kind,
	})
	doc := apiDoc.GetApiDocV2(".status.nodeStatuses")

	for _, upgrade := range upgrades.Items {
		var failures []common.Failure
		status := upgrade.GetLabels()[harvesterUpgradeStateKey]
		if status != harvesterUpgradeSuccessStatus {
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("harvester upgrade %s not yet completed, current status is %s", upgrade.Name, status),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{
						Unmasked: upgrade.Name,
						Masked:   util.MaskString(upgrade.Name),
					},
				},
			})
		}

		if len(failures) > 0 {
			currentAnalysis = append(currentAnalysis, common.Result{
				Kind:  kind,
				Name:  upgrade.Name,
				Error: failures,
			})
		}
	}
	return currentAnalysis, nil
}

// checkFleetBundles will attempt to verify status of fleet bundles
func (h HarvesterAnalyzer) checkFleetBundles(ctx context.Context, _ kubernetes.K8sApiReference) ([]common.Result, error) {
	var currentAnalysis []common.Result

	bundles, err := h.fleetClient.V1alpha1().Bundle().List("", metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing bundles: %v", err)
	}

	for _, bundle := range bundles.Items {
		var failures []common.Failure
		if bundle.Status.Summary.NotReady > 0 || bundle.Status.Summary.WaitApplied > 0 || bundle.Status.Summary.ErrApplied > 0 ||
			bundle.Status.Summary.OutOfSync > 0 || bundle.Status.Summary.Modified > 0 {
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("fleet bundle %s is not ready", bundle.Name),
				KubernetesDoc: "",
				Sensitive: []common.Sensitive{
					{
						Unmasked: bundle.Name,
						Masked:   util.MaskString(bundle.Name),
					},
				},
			})

		}
		if len(failures) > 0 {
			currentAnalysis = append(currentAnalysis, common.Result{
				Kind:  "Bundle",
				Name:  bundle.Name,
				Error: failures,
			})
		}
	}
	return currentAnalysis, nil
}

// reconcile k8s apiservices are healthy, to ensure metrics etc are working correctly
func (h HarvesterAnalyzer) checkAPIServices(ctx context.Context, apiDoc kubernetes.K8sApiReference) ([]common.Result, error) {
	var currentAnalysis []common.Result
	kind := "APIService"
	apiDoc.Kind = kind
	AnalyzerErrorsMetric.DeletePartialMatch(map[string]string{
		"analyzer_name": kind,
	})
	doc := apiDoc.GetApiDocV2(".status")

	apiservices, err := h.aggregatorClient.ApiregistrationV1().APIServices().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, apiservice := range apiservices.Items {
		var failures []common.Failure
		for _, condition := range apiservice.Status.Conditions {
			if condition.Type == apiregistrationv1.Available && condition.Status != apiregistrationv1.ConditionTrue {
				failures = append(failures, common.Failure{
					Text:          fmt.Sprintf("k8s aggregation apiservice %s is not available", apiservice.Name),
					KubernetesDoc: doc,
					Sensitive: []common.Sensitive{
						{
							Unmasked: apiservice.Name,
							Masked:   util.MaskString(apiservice.Name),
						},
					},
				})
			}
		}

		if len(failures) > 0 {
			currentAnalysis = append(currentAnalysis, common.Result{
				Kind:  kind,
				Name:  apiservice.Name,
				Error: failures,
			})
		}
	}
	return currentAnalysis, nil
}

// reconcile pcidevice plugin status reported by node matches actual number of enabled devices
// this is an easy way of identifying possible issues while enabling a particular device type
func (h HarvesterAnalyzer) checkPCIDeviceClaims(ctx context.Context, apiDoc kubernetes.K8sApiReference) ([]common.Result, error) {
	_, err := h.apiClient.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, pciDeviceCRDName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil // crd not found, likely addon is not installed
		}
		return nil, err
	}
	var currentAnalysis []common.Result
	kind := "Node"
	apiDoc.Kind = kind
	AnalyzerErrorsMetric.DeletePartialMatch(map[string]string{
		"analyzer_name": kind,
	})
	doc := apiDoc.GetApiDocV2(".status")

	// list all nodes since we need to reconcile pcidevice claims and devices from all nodes
	nodes, err := h.client.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing nodes: %v", err)
	}

	pcideviceClaimList, err := h.pciClient.DevicesV1beta1().PCIDeviceClaims().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing pcideviceclaims: %v", err)
	}

	deviceMap, nodeMap := generateNodeDeviceMap(*nodes, *pcideviceClaimList)
	// loop over nodes and identify pcidevices
	for name, node := range nodeMap {
		var failures []common.Failure
		devices, ok := deviceMap[name]
		if !ok {
			continue
		}
		deviceCapacity := make(map[string]int64)
		for _, v := range devices {
			// find device for each claim item
			device, err := h.pciClient.DevicesV1beta1().PCIDevices().Get(ctx, v, metav1.GetOptions{})
			if err != nil {
				return nil, fmt.Errorf("error fetching pcidevice: %v", err)
			}
			val := deviceCapacity[device.Status.ResourceName]
			val++
			deviceCapacity[device.Status.ResourceName] = val
		}
		// check if deviceCapacity matches node advertised capacity to ensure all devices are available
		failures = nodeCapacityCheck(node, deviceCapacity, doc)

		if len(failures) > 0 {
			currentAnalysis = append(currentAnalysis, common.Result{
				Kind:  kind,
				Name:  node.Name,
				Error: failures,
			})
		}
	}
	return currentAnalysis, nil
}

// reconcile vgpuDevice plugin status reported by node matches actual number of enabled devices
// this is an easy way of identifying possible issues while enabling a particular device type
func (h HarvesterAnalyzer) checkVGPUDevices(ctx context.Context, apiDoc kubernetes.K8sApiReference) ([]common.Result, error) {
	_, err := h.apiClient.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, vgpuDeviceCRDName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil // crd not found, likely addon is not installed
		}
		return nil, err
	}
	var currentAnalysis []common.Result
	kind := "Node"
	apiDoc.Kind = kind
	AnalyzerErrorsMetric.DeletePartialMatch(map[string]string{
		"analyzer_name": kind,
	})
	doc := apiDoc.GetApiDocV2(".status")

	// list all nodes since we need to reconcile pcidevice claims and devices from all nodes
	nodes, err := h.client.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing nodes: %v", err)
	}

	// loop over nodes and identify pcidevices
	for _, node := range nodes.Items {
		var failures []common.Failure
		deviceCapacity := make(map[string]int64)
		vGPUDevices, err := h.pciClient.DevicesV1beta1().VGPUDevices().List(ctx, metav1.ListOptions{
			LabelSelector: fmt.Sprintf("nodename=%s", node.Name),
		})
		if err != nil {
			return nil, fmt.Errorf("error listing pcideviceclaims: %v", err)
		}
		for _, vgpu := range vGPUDevices.Items {
			if vgpu.Spec.Enabled && vgpu.Status.ConfiguredVGPUTypeName != "" {
				resourceName := gpuhelper.GenerateDeviceName(vgpu.Status.ConfiguredVGPUTypeName)
				// track VGPU device count
				val := deviceCapacity[resourceName]
				val++
				deviceCapacity[resourceName] = val
			}

		}

		failures = nodeCapacityCheck(node, deviceCapacity, doc)

		if len(failures) > 0 {
			currentAnalysis = append(currentAnalysis, common.Result{
				Kind:  kind,
				Name:  node.Name,
				Error: failures,
			})
		}
	}
	return currentAnalysis, nil
}

func nodeCapacityCheck(node corev1.Node, deviceCapacity map[string]int64, doc string) []common.Failure {
	var failures []common.Failure
	for resourceName, count := range deviceCapacity {
		currentVal, ok := node.Status.Capacity[corev1.ResourceName(resourceName)]
		if !ok {
			failures = append(failures, common.Failure{
				Text:          fmt.Sprintf("expected resource %s to be advertised on node by device plugin but not found", resourceName),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{
						Unmasked: resourceName,
						Masked:   util.MaskString(resourceName),
					},
				},
			})
		} else {
			// compare if values match expected devices
			if currentVal.Value() < count {
				failures = append(failures, common.Failure{
					Text:          fmt.Sprintf("expected resource %s count to be  advertised on node by device plugin %d but found %d", resourceName, count, currentVal.Value()),
					KubernetesDoc: doc,
					Sensitive: []common.Sensitive{
						{
							Unmasked: resourceName,
							Masked:   util.MaskString(resourceName),
						},
					},
				})
			}
		}
	}
	return failures
}

func generateNodeDeviceMap(nodeList corev1.NodeList, deviceClaimList v1beta1.PCIDeviceClaimList) (map[string][]string, map[string]corev1.Node) {
	deviceMap := make(map[string][]string)
	nodeMap := make(map[string]corev1.Node)
	for _, device := range deviceClaimList.Items {
		currentDevices := deviceMap[device.Spec.NodeName]
		currentDevices = append(currentDevices, device.Name)
		deviceMap[device.Spec.NodeName] = currentDevices
	}

	for _, node := range nodeList.Items {
		nodeMap[node.Name] = node
	}
	return deviceMap, nodeMap
}
