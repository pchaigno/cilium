// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	_ "embed"
	goerrors "errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	v1client "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/k8s"
	k8sconstv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sconstv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/versioncheck"
)

const (
	// subsysK8s is the value for logfields.LogSubsys
	subsysK8s = "k8s"

	// CNPCRDName is the full name of the CNP CRD.
	CNPCRDName = k8sconstv2.CNPKindDefinition + "/" + k8sconstv2.CustomResourceDefinitionVersion

	// CCNPCRDName is the full name of the CCNP CRD.
	CCNPCRDName = k8sconstv2.CCNPKindDefinition + "/" + k8sconstv2.CustomResourceDefinitionVersion

	// CEPCRDName is the full name of the CEP CRD.
	CEPCRDName = k8sconstv2.CEPKindDefinition + "/" + k8sconstv2.CustomResourceDefinitionVersion

	// CIDCRDName is the full name of the CID CRD.
	CIDCRDName = k8sconstv2.CIDKindDefinition + "/" + k8sconstv2.CustomResourceDefinitionVersion

	// CNCRDName is the full name of the CN CRD.
	CNCRDName = k8sconstv2.CNKindDefinition + "/" + k8sconstv2.CustomResourceDefinitionVersion

	// CEWCRDName is the full name of the CEW CRD.
	CEWCRDName = k8sconstv2.CEWKindDefinition + "/" + k8sconstv2.CustomResourceDefinitionVersion

	// CLRPCRDName is the full name of the CLRP CRD.
	CLRPCRDName = k8sconstv2.CLRPKindDefinition + "/" + k8sconstv2.CustomResourceDefinitionVersion

	// CENPCRDName is the full name of the CENP CRD.
	CENPCRDName = k8sconstv2alpha1.CENPKindDefinition + "/" + k8sconstv2alpha1.CustomResourceDefinitionVersion

	// CESCRDName is the full name of the CES CRD.
	CESCRDName = k8sconstv2alpha1.CESKindDefinition + "/" + k8sconstv2alpha1.CustomResourceDefinitionVersion

	// CESRPCRDName is the full name of the CESRP CRD.
	CESRPCRDName = k8sconstv2alpha1.CESRPKindDefinition + "/" + k8sconstv2alpha1.CustomResourceDefinitionVersion
)

var (
	// log is the k8s package logger object.
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsysK8s)

	comparableCRDSchemaVersion = versioncheck.MustVersion(k8sconstv2.CustomResourceDefinitionSchemaVersion)
)

type crdCreationFn func(clientset apiextensionsclient.Interface) error

// CreateCustomResourceDefinitions creates our CRD objects in the Kubernetes
// cluster.
func CreateCustomResourceDefinitions(clientset apiextensionsclient.Interface) error {
	g, _ := errgroup.WithContext(context.Background())

	resourceToCreateFnMapping := map[string]crdCreationFn{
		synced.CRDResourceName(k8sconstv2.CNPName):         createCNPCRD,
		synced.CRDResourceName(k8sconstv2.CCNPName):        createCCNPCRD,
		synced.CRDResourceName(k8sconstv2.CNName):          createNodeCRD,
		synced.CRDResourceName(k8sconstv2.CIDName):         createIdentityCRD,
		synced.CRDResourceName(k8sconstv2.CEPName):         createCEPCRD,
		synced.CRDResourceName(k8sconstv2.CEWName):         createCEWCRD,
		synced.CRDResourceName(k8sconstv2.CLRPName):        createCLRPCRD,
		synced.CRDResourceName(k8sconstv2alpha1.CENPName):  createCENPCRD,
		synced.CRDResourceName(k8sconstv2alpha1.CESName):   createCESCRD,
		synced.CRDResourceName(k8sconstv2alpha1.CESRPName): createCESRPCRD,
	}
	for _, r := range synced.AllCRDResourceNames() {
		fn, ok := resourceToCreateFnMapping[r]
		if !ok {
			log.Fatalf("Unknown resource %s. Please update pkg/k8s/apis/cilium.io/client to understand this type.", r)
		}
		g.Go(func() error {
			return fn(clientset)
		})
	}

	return g.Wait()
}

var (
	//go:embed crds/v2/ciliumnetworkpolicies.yaml
	crdsCiliumnetworkpolicies []byte

	//go:embed crds/v2/ciliumclusterwidenetworkpolicies.yaml
	crdsCiliumclusterwidenetworkpolicies []byte

	//go:embed crds/v2/ciliumendpoints.yaml
	crdsCiliumendpoints []byte

	//go:embed crds/v2/ciliumidentities.yaml
	crdsCiliumidentities []byte

	//go:embed crds/v2/ciliumnodes.yaml
	crdsCiliumnodes []byte

	//go:embed crds/v2/ciliumexternalworkloads.yaml
	crdsCiliumexternalworkloads []byte

	//go:embed crds/v2/ciliumlocalredirectpolicies.yaml
	crdsCiliumlocalredirectpolicies []byte

	//go:embed crds/v2alpha1/ciliumegressnatpolicies.yaml
	crdsv2Alpha1Ciliumegressnatpolicies []byte

	//go:embed crds/v2alpha1/ciliumendpointslices.yaml
	crdsv2Alpha1Ciliumendpointslices []byte

	//go:embed crds/v2alpha1/ciliumegresssrv6policies.yaml
	crdsv2Alpha1Ciliumegresssrv6policies []byte
)

// GetPregeneratedCRD returns the pregenerated CRD based on the requested CRD
// name. The pregenerated CRDs are generated by the controller-gen tool and
// serialized into binary form by go-bindata. This function retrieves CRDs from
// the binary form.
func GetPregeneratedCRD(crdName string) apiextensionsv1.CustomResourceDefinition {
	var (
		err      error
		crdBytes []byte
	)

	scopedLog := log.WithField("crdName", crdName)

	switch crdName {
	case CNPCRDName:
		crdBytes = crdsCiliumnetworkpolicies
	case CCNPCRDName:
		crdBytes = crdsCiliumclusterwidenetworkpolicies
	case CEPCRDName:
		crdBytes = crdsCiliumendpoints
	case CIDCRDName:
		crdBytes = crdsCiliumidentities
	case CNCRDName:
		crdBytes = crdsCiliumnodes
	case CEWCRDName:
		crdBytes = crdsCiliumexternalworkloads
	case CLRPCRDName:
		crdBytes = crdsCiliumlocalredirectpolicies
	case CENPCRDName:
		crdBytes = crdsv2Alpha1Ciliumegressnatpolicies
	case CESCRDName:
		crdBytes = crdsv2Alpha1Ciliumendpointslices
	case CESRPCRDName:
		crdBytes = crdsv2Alpha1Ciliumegresssrv6policies
	default:
		scopedLog.Fatal("Pregenerated CRD does not exist")
	}

	ciliumCRD := apiextensionsv1.CustomResourceDefinition{}
	err = yaml.Unmarshal(crdBytes, &ciliumCRD)
	if err != nil {
		scopedLog.WithError(err).Fatal("Error unmarshalling pregenerated CRD")
	}

	return ciliumCRD
}

// createCNPCRD creates and updates the CiliumNetworkPolicies CRD. It should be called
// on agent startup but is idempotent and safe to call again.
func createCNPCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(CNPCRDName)

	return createUpdateCRD(
		clientset,
		CNPCRDName,
		constructV1CRD(k8sconstv2.CNPName, ciliumCRD),
		newDefaultPoller(),
	)
}

// createCCNPCRD creates and updates the CiliumClusterwideNetworkPolicy CRD. It
// should be called on agent startup but is idempotent and safe to call again.
func createCCNPCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(CCNPCRDName)

	return createUpdateCRD(
		clientset,
		CCNPCRDName,
		constructV1CRD(k8sconstv2.CCNPName, ciliumCRD),
		newDefaultPoller(),
	)
}

// createCEPCRD creates and updates the CiliumEndpoint CRD. It should be called
// on agent startup but is idempotent and safe to call again.
func createCEPCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(CEPCRDName)

	return createUpdateCRD(
		clientset,
		CEPCRDName,
		constructV1CRD(k8sconstv2.CEPName, ciliumCRD),
		newDefaultPoller(),
	)
}

// createNodeCRD creates and updates the CiliumNode CRD. It should be called on
// agent startup but is idempotent and safe to call again.
func createNodeCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(CNCRDName)

	return createUpdateCRD(
		clientset,
		CNCRDName,
		constructV1CRD(k8sconstv2.CNName, ciliumCRD),
		newDefaultPoller(),
	)
}

// createCEWCRD creates and updates the CiliumExternalWorkload CRD. It should be called on
// agent startup but is idempotent and safe to call again.
func createCEWCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(CEWCRDName)

	return createUpdateCRD(
		clientset,
		CEWCRDName,
		constructV1CRD(k8sconstv2.CEWName, ciliumCRD),
		newDefaultPoller(),
	)
}

// createIdentityCRD creates and updates the CiliumIdentity CRD. It should be
// called on agent startup but is idempotent and safe to call again.
func createIdentityCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(CIDCRDName)

	return createUpdateCRD(
		clientset,
		CIDCRDName,
		constructV1CRD(k8sconstv2.CIDName, ciliumCRD),
		newDefaultPoller(),
	)
}

func createCLRPCRD(clientset apiextensionsclient.Interface) error {
	cLrpCRD := GetPregeneratedCRD(CLRPCRDName)

	return createUpdateCRD(
		clientset,
		CLRPCRDName,
		constructV1CRD(k8sconstv2.CLRPName, cLrpCRD),
		newDefaultPoller(),
	)
}

func createCENPCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(CENPCRDName)

	return createUpdateCRD(
		clientset,
		CENPCRDName,
		constructV1CRD(k8sconstv2alpha1.CENPName, ciliumCRD),
		newDefaultPoller(),
	)
}

// createCESCRD creates and updates the CiliumEndpointSlice CRD. It should be
// called on agent startup but is idempotent and safe to call again.
func createCESCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(CESCRDName)

	return createUpdateCRD(
		clientset,
		CESCRDName,
		constructV1CRD(k8sconstv2alpha1.CESName, ciliumCRD),
		newDefaultPoller(),
	)
}

func createCESRPCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(CESRPCRDName)

	return createUpdateCRD(
		clientset,
		CESRPCRDName,
		constructV1CRD(k8sconstv2alpha1.CESRPName, ciliumCRD),
		newDefaultPoller(),
	)
}

// createUpdateCRD ensures the CRD object is installed into the K8s cluster. It
// will create or update the CRD and its validation schema as necessary. This
// function only accepts v1 CRD objects, and defers to its v1beta1 variant if
// the cluster only supports v1beta1 CRDs. This allows us to convert all our
// CRDs into v1 form and only perform conversions on-demand, simplifying the
// code.
func createUpdateCRD(
	clientset apiextensionsclient.Interface,
	crdName string,
	crd *apiextensionsv1.CustomResourceDefinition,
	poller poller,
) error {
	scopedLog := log.WithField("name", crdName)

	if !k8sversion.Capabilities().APIExtensionsV1CRD {
		log.Infof("K8s apiserver does not support v1 CRDs, falling back to v1beta1")

		return createUpdateV1beta1CRD(
			scopedLog,
			clientset.ApiextensionsV1beta1(),
			crdName,
			crd,
			poller,
		)
	}

	v1CRDClient := clientset.ApiextensionsV1()
	clusterCRD, err := v1CRDClient.CustomResourceDefinitions().Get(
		context.TODO(),
		crd.ObjectMeta.Name,
		metav1.GetOptions{})
	if errors.IsNotFound(err) {
		scopedLog.Info("Creating CRD (CustomResourceDefinition)...")

		clusterCRD, err = v1CRDClient.CustomResourceDefinitions().Create(
			context.TODO(),
			crd,
			metav1.CreateOptions{})
		// This occurs when multiple agents race to create the CRD. Since another has
		// created it, it will also update it, hence the non-error return.
		if errors.IsAlreadyExists(err) {
			return nil
		}
	}
	if err != nil {
		return err
	}

	if err := updateV1CRD(scopedLog, crd, clusterCRD, v1CRDClient, poller); err != nil {
		return err
	}
	if err := waitForV1CRD(scopedLog, crdName, clusterCRD, v1CRDClient, poller); err != nil {
		return err
	}

	scopedLog.Info("CRD (CustomResourceDefinition) is installed and up-to-date")

	return nil
}

func constructV1CRD(
	name string,
	template apiextensionsv1.CustomResourceDefinition,
) *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				k8sconstv2.CustomResourceDefinitionSchemaVersionKey: k8sconstv2.CustomResourceDefinitionSchemaVersion,
			},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: k8sconstv2.CustomResourceDefinitionGroup,
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:       template.Spec.Names.Kind,
				Plural:     template.Spec.Names.Plural,
				ShortNames: template.Spec.Names.ShortNames,
				Singular:   template.Spec.Names.Singular,
			},
			Scope:    template.Spec.Scope,
			Versions: template.Spec.Versions,
		},
	}
}

func needsUpdateV1(clusterCRD *apiextensionsv1.CustomResourceDefinition) bool {
	if clusterCRD.Spec.Versions[0].Schema == nil {
		// no validation detected
		return true
	}
	v, ok := clusterCRD.Labels[k8sconstv2.CustomResourceDefinitionSchemaVersionKey]
	if !ok {
		// no schema version detected
		return true
	}

	clusterVersion, err := versioncheck.Version(v)
	if err != nil || clusterVersion.LT(comparableCRDSchemaVersion) {
		// version in cluster is either unparsable or smaller than current version
		return true
	}

	return false
}

func updateV1CRD(
	scopedLog *logrus.Entry,
	crd, clusterCRD *apiextensionsv1.CustomResourceDefinition,
	client v1client.CustomResourceDefinitionsGetter,
	poller poller,
) error {
	scopedLog.Debug("Checking if CRD (CustomResourceDefinition) needs update...")

	if crd.Spec.Versions[0].Schema != nil && needsUpdateV1(clusterCRD) {
		scopedLog.Info("Updating CRD (CustomResourceDefinition)...")

		// Update the CRD with the validation schema.
		err := poller.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
			var err error
			clusterCRD, err = client.CustomResourceDefinitions().Get(
				context.TODO(),
				crd.ObjectMeta.Name,
				metav1.GetOptions{})
			if err != nil {
				return false, err
			}

			// This seems too permissive but we only get here if the version is
			// different per needsUpdate above. If so, we want to update on any
			// validation change including adding or removing validation.
			if needsUpdateV1(clusterCRD) {
				scopedLog.Debug("CRD validation is different, updating it...")

				clusterCRD.ObjectMeta.Labels = crd.ObjectMeta.Labels
				clusterCRD.Spec = crd.Spec

				// Even though v1 CRDs omit this field by default (which also
				// means it's false) it is still carried over from the previous
				// CRD. Therefore, we must set this to false explicitly because
				// the apiserver will carry over the old value (true).
				clusterCRD.Spec.PreserveUnknownFields = false

				_, err := client.CustomResourceDefinitions().Update(
					context.TODO(),
					clusterCRD,
					metav1.UpdateOptions{})
				switch {
				case errors.IsConflict(err): // Occurs as Operators race to update CRDs.
					scopedLog.WithError(err).
						Debug("The CRD update was based on an older version, retrying...")
					return false, nil
				case err == nil:
					return true, nil
				}

				scopedLog.WithError(err).Debug("Unable to update CRD validation")

				return false, err
			}

			return true, nil
		})
		if err != nil {
			scopedLog.WithError(err).Error("Unable to update CRD")
			return err
		}
	}

	return nil
}

func waitForV1CRD(
	scopedLog *logrus.Entry,
	crdName string,
	crd *apiextensionsv1.CustomResourceDefinition,
	client v1client.CustomResourceDefinitionsGetter,
	poller poller,
) error {
	scopedLog.Debug("Waiting for CRD (CustomResourceDefinition) to be available...")

	err := poller.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		for _, cond := range crd.Status.Conditions {
			switch cond.Type {
			case apiextensionsv1.Established:
				if cond.Status == apiextensionsv1.ConditionTrue {
					return true, nil
				}
			case apiextensionsv1.NamesAccepted:
				if cond.Status == apiextensionsv1.ConditionFalse {
					err := goerrors.New(cond.Reason)
					scopedLog.WithError(err).Error("Name conflict for CRD")
					return false, err
				}
			}
		}

		var err error
		if crd, err = client.CustomResourceDefinitions().Get(
			context.TODO(),
			crd.ObjectMeta.Name,
			metav1.GetOptions{}); err != nil {
			return false, err
		}
		return false, err
	})
	if err != nil {
		return fmt.Errorf("error occurred waiting for CRD: %w", err)
	}

	return nil
}

// poller is an interface that abstracts the polling logic when dealing with
// CRD changes / updates to the apiserver. The reason this exists is mainly for
// unit-testing.
type poller interface {
	Poll(interval, duration time.Duration, conditionFn func() (bool, error)) error
}

func newDefaultPoller() defaultPoll {
	return defaultPoll{}
}

type defaultPoll struct{}

func (p defaultPoll) Poll(
	interval, duration time.Duration,
	conditionFn func() (bool, error),
) error {
	return wait.Poll(interval, duration, conditionFn)
}

// RegisterCRDs registers all CRDs with the K8s apiserver.
func RegisterCRDs() error {
	if err := CreateCustomResourceDefinitions(k8s.APIExtClient()); err != nil {
		return fmt.Errorf("Unable to create custom resource definition: %s", err)
	}

	return nil
}
