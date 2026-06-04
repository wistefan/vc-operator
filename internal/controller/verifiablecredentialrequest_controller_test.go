/*
Copyright 2026 Seamless Middleware Technologies S.L and/or its affiliates
and other contributors as indicated by the @author tags.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vcv1alpha1 "github.com/wistefan/vc-operator/api/v1alpha1"
	"github.com/wistefan/vc-operator/internal/credential"
	"github.com/wistefan/vc-operator/internal/credentialstore"
	"github.com/wistefan/vc-operator/internal/oid4vci"
)

// mockCredentialStore is a configurable mock implementation of
// credentialstore.CredentialStore for testing the VCRequest controller
// without depending on a real storage backend.
type mockCredentialStore struct {
	storeFunc    func(ctx context.Context, ref credentialstore.TargetRef, data *credentialstore.CredentialData) error
	retrieveFunc func(ctx context.Context, ref credentialstore.TargetRef) (*credentialstore.CredentialData, error)
	deleteFunc   func(ctx context.Context, ref credentialstore.TargetRef) error

	// storeCalls tracks the number of Store calls for assertion purposes.
	storeCalls int
	// lastStored captures the last CredentialData passed to Store.
	lastStored *credentialstore.CredentialData
	// lastRef captures the last TargetRef passed to Store.
	lastRef *credentialstore.TargetRef
}

// Store delegates to the configured mock function or succeeds by default.
func (m *mockCredentialStore) Store(ctx context.Context, ref credentialstore.TargetRef, data *credentialstore.CredentialData) error {
	m.storeCalls++
	m.lastStored = data
	m.lastRef = &ref
	if m.storeFunc != nil {
		return m.storeFunc(ctx, ref, data)
	}
	return nil
}

// Retrieve delegates to the configured mock function or returns not found.
func (m *mockCredentialStore) Retrieve(ctx context.Context, ref credentialstore.TargetRef) (*credentialstore.CredentialData, error) {
	if m.retrieveFunc != nil {
		return m.retrieveFunc(ctx, ref)
	}
	return nil, fmt.Errorf("not found")
}

// Delete delegates to the configured mock function or succeeds by default.
func (m *mockCredentialStore) Delete(ctx context.Context, ref credentialstore.TargetRef) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, ref)
	}
	return nil
}

// buildTestJWT creates a compact-serialized JWT with the given claims for testing.
// It uses a dummy header and signature — only the payload is meaningful for parsing.
func buildTestJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))

	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signature := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))

	return header + "." + payload + "." + signature
}

// buildTestJWTWithExpiry creates a JWT with iat and exp claims set relative to
// the reference time.
func buildTestJWTWithExpiry(iat time.Time, expiry time.Time) string {
	claims := map[string]interface{}{
		"iat": float64(iat.Unix()),
		"exp": float64(expiry.Unix()),
		"sub": "test-subject",
		"iss": "https://issuer.example.com",
	}
	return buildTestJWT(claims)
}

var _ = Describe("VerifiableCredentialRequest Controller", func() {
	const (
		vcReqName      = "test-vcreq"
		vcReqNs        = "default"
		issuerName     = "test-vc-issuer"
		authSecretName = "test-vc-auth-secret"
		targetSecret   = "test-target-secret"
		credType       = "VerifiableCredential"
	)

	var (
		typeNamespacedName types.NamespacedName
		mockOID4VCI        *mockOID4VCIClient
		mockStore          *mockCredentialStore
		eventRecorder      *record.FakeRecorder
		reconciler         *VerifiableCredentialRequestReconciler
	)

	BeforeEach(func() {
		typeNamespacedName = types.NamespacedName{
			Name:      vcReqName,
			Namespace: vcReqNs,
		}
		mockOID4VCI = &mockOID4VCIClient{}
		mockStore = &mockCredentialStore{}
		eventRecorder = record.NewFakeRecorder(fakeEventBufferSize)
		reconciler = &VerifiableCredentialRequestReconciler{
			Client:          k8sClient,
			Scheme:          k8sClient.Scheme(),
			OID4VCIClient:   mockOID4VCI,
			CredentialStore: mockStore,
			EventRecorder:   eventRecorder,
		}
	})

	// createReadyIssuer creates a CredentialIssuer CR and sets its status to Ready
	// with populated endpoints.
	createReadyIssuer := func(ctx context.Context) {
		issuer := &vcv1alpha1.CredentialIssuer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      issuerName,
				Namespace: vcReqNs,
			},
			Spec: vcv1alpha1.CredentialIssuerSpec{
				IssuerURL:     "https://issuer.example.com",
				AuthSecretRef: vcv1alpha1.SecretReference{Name: authSecretName},
			},
		}
		Expect(k8sClient.Create(ctx, issuer)).To(Succeed())

		// Update status with Ready condition and endpoints.
		Eventually(func() error {
			var fetched vcv1alpha1.CredentialIssuer
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: issuerName, Namespace: vcReqNs}, &fetched); err != nil {
				return err
			}
			fetched.Status.CredentialEndpoint = "https://issuer.example.com/credentials"
			fetched.Status.TokenEndpoint = "https://issuer.example.com/token"
			fetched.Status.SupportedCredentialTypes = []string{"VerifiableCredential"}
			meta.SetStatusCondition(&fetched.Status.Conditions, metav1.Condition{
				Type:               vcv1alpha1.ConditionTypeReady,
				Status:             metav1.ConditionTrue,
				Reason:             vcv1alpha1.ReasonMetadataDiscovered,
				Message:            "Issuer is ready",
				ObservedGeneration: fetched.Generation,
			})
			return k8sClient.Status().Update(ctx, &fetched)
		}).Should(Succeed())
	}

	// createNotReadyIssuer creates a CredentialIssuer CR without a Ready condition.
	createNotReadyIssuer := func(ctx context.Context) {
		issuer := &vcv1alpha1.CredentialIssuer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      issuerName,
				Namespace: vcReqNs,
			},
			Spec: vcv1alpha1.CredentialIssuerSpec{
				IssuerURL:     "https://issuer.example.com",
				AuthSecretRef: vcv1alpha1.SecretReference{Name: authSecretName},
			},
		}
		Expect(k8sClient.Create(ctx, issuer)).To(Succeed())
	}

	// createAuthSecret creates an auth Secret with client_credentials keys.
	createAuthSecret := func(ctx context.Context) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      authSecretName,
				Namespace: vcReqNs,
			},
			Data: map[string][]byte{
				AuthSecretKeyClientID:     []byte("test-client-id"),
				AuthSecretKeyClientSecret: []byte("test-client-secret"),
			},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	}

	// createVCRequest creates a VerifiableCredentialRequest CR.
	createVCRequest := func(ctx context.Context) {
		vcReq := &vcv1alpha1.VerifiableCredentialRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name:      vcReqName,
				Namespace: vcReqNs,
			},
			Spec: vcv1alpha1.VerifiableCredentialRequestSpec{
				IssuerRef:      vcv1alpha1.LocalObjectReference{Name: issuerName},
				CredentialType: credType,
				Format:         "jwt_vc_json",
				TargetSecretRef: vcv1alpha1.TargetSecretReference{
					Name: targetSecret,
					Key:  "credential",
				},
			},
		}
		Expect(k8sClient.Create(ctx, vcReq)).To(Succeed())
	}

	// deleteResource deletes a resource if it exists, ignoring not-found errors.
	deleteResource := func(ctx context.Context, obj client.Object, name string) {
		key := types.NamespacedName{Name: name, Namespace: vcReqNs}
		if err := k8sClient.Get(ctx, key, obj); err == nil {
			_ = k8sClient.Delete(ctx, obj)
		}
	}

	// getVCRequestStatus fetches the current VCRequest and returns its status.
	getVCRequestStatus := func(ctx context.Context) vcv1alpha1.VerifiableCredentialRequestStatus {
		var vcReq vcv1alpha1.VerifiableCredentialRequest
		key := types.NamespacedName{Name: vcReqName, Namespace: vcReqNs}
		Expect(k8sClient.Get(ctx, key, &vcReq)).To(Succeed())
		return vcReq.Status
	}

	// setupHappyPath configures mocks for a successful credential issuance flow.
	setupHappyPath := func() {
		now := time.Now()
		expiry := now.Add(1 * time.Hour)
		testJWT := buildTestJWTWithExpiry(now, expiry)

		mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, _ oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
			return &oid4vci.TokenResponse{
				AccessToken: "test-access-token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			}, nil
		}
		mockOID4VCI.requestCredentialFunc = func(_ context.Context, _ string, _ string, _ oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
			return &oid4vci.CredentialResponse{
				Credential: testJWT,
				Format:     "jwt_vc_json",
			}, nil
		}
	}

	Context("when the VerifiableCredentialRequest resource is not found", func() {
		It("should return without error and not requeue", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "nonexistent",
					Namespace: vcReqNs,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ctrl.Result{}))
		})
	})

	Context("when the referenced CredentialIssuer does not exist", func() {
		BeforeEach(func() {
			createVCRequest(ctx)
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
		})

		It("should set Ready=False with IssuerNotFound reason", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(IssuerNotReadyRequeueInterval))

			status := getVCRequestStatus(ctx)
			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal(vcv1alpha1.ReasonIssuerNotFound))

			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Status).To(Equal(metav1.ConditionTrue))
		})

		It("should record a warning event for the missing issuer", func() {
			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).To(ContainSubstring(vcv1alpha1.ReasonIssuerNotFound))
		})
	})

	Context("when the referenced CredentialIssuer is not Ready", func() {
		BeforeEach(func() {
			createNotReadyIssuer(ctx)
			createVCRequest(ctx)
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
		})

		It("should set Ready=False with IssuerNotReady reason", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(IssuerNotReadyRequeueInterval))

			status := getVCRequestStatus(ctx)
			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal(vcv1alpha1.ReasonIssuerNotReady))
		})

		It("should record a warning event for the not-ready issuer", func() {
			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).To(ContainSubstring(vcv1alpha1.ReasonIssuerNotReady))
		})
	})

	Context("when the auth Secret is not found", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createVCRequest(ctx)
			// Do NOT create the auth secret.
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
		})

		It("should set Ready=False with AuthSecretNotFound reason", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(ConfigErrorRequeueInterval))

			status := getVCRequestStatus(ctx)
			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal(vcv1alpha1.ReasonAuthSecretNotFound))
		})
	})

	Context("when the token request fails", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)
			mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, _ oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
				return nil, fmt.Errorf("token endpoint unreachable")
			}
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should set Error condition with TokenRequestFailed reason and return error for backoff", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("token endpoint unreachable"))

			status := getVCRequestStatus(ctx)
			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(errorCondition.Reason).To(Equal(vcv1alpha1.ReasonTokenRequestFailed))
		})

		It("should record a warning event for the token failure", func() {
			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).To(ContainSubstring(vcv1alpha1.ReasonTokenRequestFailed))
		})
	})

	Context("when the credential request fails", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)
			mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, _ oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
				return &oid4vci.TokenResponse{
					AccessToken: "test-access-token",
					TokenType:   "Bearer",
				}, nil
			}
			mockOID4VCI.requestCredentialFunc = func(_ context.Context, _ string, _ string, _ oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
				return nil, fmt.Errorf("credential endpoint error")
			}
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should set Error condition with CredentialRequestFailed reason", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("credential endpoint error"))

			status := getVCRequestStatus(ctx)
			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Reason).To(Equal(vcv1alpha1.ReasonCredentialRequestFailed))
		})
	})

	Context("when credential storage fails", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)

			now := time.Now()
			expiry := now.Add(1 * time.Hour)
			testJWT := buildTestJWTWithExpiry(now, expiry)

			mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, _ oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
				return &oid4vci.TokenResponse{AccessToken: "token", TokenType: "Bearer"}, nil
			}
			mockOID4VCI.requestCredentialFunc = func(_ context.Context, _ string, _ string, _ oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
				return &oid4vci.CredentialResponse{Credential: testJWT, Format: "jwt_vc_json"}, nil
			}
			mockStore.storeFunc = func(_ context.Context, _ credentialstore.TargetRef, _ *credentialstore.CredentialData) error {
				return fmt.Errorf("storage backend unavailable")
			}
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should set Error condition with StorageFailed reason and return error for backoff", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("storage backend unavailable"))

			status := getVCRequestStatus(ctx)
			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Reason).To(Equal(vcv1alpha1.ReasonStorageFailed))
		})
	})

	Context("when the credential response is not a string", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)

			mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, _ oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
				return &oid4vci.TokenResponse{AccessToken: "token", TokenType: "Bearer"}, nil
			}
			mockOID4VCI.requestCredentialFunc = func(_ context.Context, _ string, _ string, _ oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
				// Return a non-string credential (JSON-LD format).
				return &oid4vci.CredentialResponse{
					Credential: map[string]interface{}{"@context": "test"},
					Format:     "ldp_vc",
				}, nil
			}
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should set Error condition for non-string credential response", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(ConfigErrorRequeueInterval))

			status := getVCRequestStatus(ctx)
			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Reason).To(Equal(vcv1alpha1.ReasonCredentialRequestFailed))
			Expect(errorCondition.Message).To(ContainSubstring("did not contain a string credential"))
		})
	})

	Context("happy path: full credential issuance flow", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)
			setupHappyPath()
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should set Ready=True and CredentialIssued=True conditions", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			status := getVCRequestStatus(ctx)

			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(readyCondition.Reason).To(Equal(vcv1alpha1.ReasonCredentialObtained))

			issuedCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeCredentialIssued)
			Expect(issuedCondition).NotTo(BeNil())
			Expect(issuedCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(issuedCondition.Reason).To(Equal(vcv1alpha1.ReasonCredentialObtained))
		})

		It("should set RenewalScheduled condition", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status := getVCRequestStatus(ctx)
			renewalCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeRenewalScheduled)
			Expect(renewalCondition).NotTo(BeNil())
			Expect(renewalCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(renewalCondition.Reason).To(Equal(vcv1alpha1.ReasonRenewalScheduled))
		})

		It("should clear Error condition on success", func() {
			// First, induce an error condition.
			failStore := &mockCredentialStore{
				storeFunc: func(_ context.Context, _ credentialstore.TargetRef, _ *credentialstore.CredentialData) error {
					return fmt.Errorf("transient failure")
				},
			}
			failReconciler := &VerifiableCredentialRequestReconciler{
				Client:          k8sClient,
				Scheme:          k8sClient.Scheme(),
				OID4VCIClient:   mockOID4VCI,
				CredentialStore: failStore,
				EventRecorder:   record.NewFakeRecorder(fakeEventBufferSize),
			}
			_, _ = failReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			// Verify Error condition was set.
			status := getVCRequestStatus(ctx)
			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())

			// Now succeed — Error should be cleared.
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status = getVCRequestStatus(ctx)
			errorCondition = meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).To(BeNil())
		})

		It("should populate status timestamps", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status := getVCRequestStatus(ctx)
			Expect(status.LastIssuanceTime).NotTo(BeNil())
			Expect(status.NextRenewalTime).NotTo(BeNil())
			Expect(status.CredentialExpiryTime).NotTo(BeNil())
			Expect(status.CredentialFormat).To(Equal("jwt_vc_json"))
		})

		It("should store the credential via the CredentialStore", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(mockStore.storeCalls).To(Equal(1))
			Expect(mockStore.lastStored).NotTo(BeNil())
			Expect(mockStore.lastStored.Format).To(Equal("jwt_vc_json"))
			Expect(len(mockStore.lastStored.Credential)).To(BeNumerically(">", 0))
		})

		It("should set correct TargetRef with owner information", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(mockStore.lastRef).NotTo(BeNil())
			Expect(mockStore.lastRef.Namespace).To(Equal(vcReqNs))
			Expect(mockStore.lastRef.Name).To(Equal(targetSecret))
			Expect(mockStore.lastRef.Key).To(Equal("credential"))
			Expect(mockStore.lastRef.OwnerName).To(Equal(vcReqName))
			Expect(mockStore.lastRef.OwnerGVK.Kind).To(Equal("VerifiableCredentialRequest"))
		})

		It("should record a success event", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).To(ContainSubstring(vcv1alpha1.ReasonCredentialObtained))
			Expect(event).To(ContainSubstring(credType))
		})

		It("should requeue before credential expiry", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// The JWT expires in 1 hour and renewBefore defaults to 5 minutes,
			// so requeue should be approximately 55 minutes (with tolerance).
			Expect(result.RequeueAfter).To(BeNumerically(">", 50*time.Minute))
			Expect(result.RequeueAfter).To(BeNumerically("<", 60*time.Minute))
		})
	})

	Context("happy path: credential renewal (second issuance)", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)
			setupHappyPath()
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should set LastRenewalTime on second reconciliation", func() {
			// First reconciliation — initial issuance.
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status := getVCRequestStatus(ctx)
			Expect(status.LastIssuanceTime).NotTo(BeNil())
			// First issuance should NOT set LastRenewalTime.
			Expect(status.LastRenewalTime).To(BeNil())

			// Second reconciliation — renewal.
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status = getVCRequestStatus(ctx)
			// Renewal should set LastRenewalTime.
			Expect(status.LastRenewalTime).NotTo(BeNil())
		})

		It("should record a renewal event on second issuance", func() {
			// First reconciliation.
			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			// Drain first event.
			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))

			// Second reconciliation — renewal.
			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).To(ContainSubstring("Renewed"))
		})
	})

	Context("happy path: previous credential rotation", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)
			setupHappyPath()

			// Mock the retrieve to return an existing credential for rotation.
			mockStore.retrieveFunc = func(_ context.Context, _ credentialstore.TargetRef) (*credentialstore.CredentialData, error) {
				return &credentialstore.CredentialData{
					Credential: []byte("previous-jwt-credential"),
					Format:     "jwt_vc_json",
				}, nil
			}
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should preserve the previous credential in the rotation buffer", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(mockStore.lastStored).NotTo(BeNil())
			Expect(mockStore.lastStored.PreviousCredential).To(Equal([]byte("previous-jwt-credential")))
		})
	})

	Context("happy path: credential without expiry", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)

			// Build a JWT without an exp claim.
			jwtWithoutExp := buildTestJWT(map[string]interface{}{
				"iat": float64(time.Now().Unix()),
				"sub": "test-subject",
			})

			mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, _ oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
				return &oid4vci.TokenResponse{AccessToken: "token", TokenType: "Bearer"}, nil
			}
			mockOID4VCI.requestCredentialFunc = func(_ context.Context, _ string, _ string, _ oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
				return &oid4vci.CredentialResponse{Credential: jwtWithoutExp, Format: "jwt_vc_json"}, nil
			}
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should still succeed and schedule renewal using default TTL", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			status := getVCRequestStatus(ctx)
			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionTrue))

			// No explicit expiry, so CredentialExpiryTime should be nil.
			Expect(status.CredentialExpiryTime).To(BeNil())

			// But NextRenewalTime should still be set (using default TTL).
			Expect(status.NextRenewalTime).NotTo(BeNil())
		})
	})

	Context("token auth: pre-authorized code flow", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createVCRequest(ctx)

			// Create auth secret with pre-authorized code.
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      authSecretName,
					Namespace: vcReqNs,
				},
				Data: map[string][]byte{
					AuthSecretKeyPreAuthorizedCode: []byte("pre-auth-code-123"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			setupHappyPath()
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should use pre-authorized code grant type", func() {
			var capturedAuth oid4vci.TokenAuth
			mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, auth oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
				capturedAuth = auth
				return &oid4vci.TokenResponse{AccessToken: "token", TokenType: "Bearer"}, nil
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(capturedAuth.GrantType).To(Equal(oid4vci.GrantTypePreAuthorizedCode))
			Expect(capturedAuth.PreAuthorizedCode).To(Equal("pre-auth-code-123"))
		})
	})

	Context("token auth: client credentials flow", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)
			setupHappyPath()
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should use client credentials grant type", func() {
			var capturedAuth oid4vci.TokenAuth
			mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, auth oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
				capturedAuth = auth
				return &oid4vci.TokenResponse{AccessToken: "token", TokenType: "Bearer"}, nil
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(capturedAuth.GrantType).To(Equal(oid4vci.GrantTypeClientCredentials))
			Expect(capturedAuth.ClientID).To(Equal("test-client-id"))
			Expect(capturedAuth.ClientSecret).To(Equal("test-client-secret"))
		})
	})

	Context("credential request parameters", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)
			setupHappyPath()
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should pass the correct credential type and format to the OID4VCI client", func() {
			var capturedReq oid4vci.CredentialRequest
			var capturedURL string
			var capturedToken string

			mockOID4VCI.requestCredentialFunc = func(_ context.Context, credURL string, accessToken string, req oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
				capturedReq = req
				capturedURL = credURL
				capturedToken = accessToken

				now := time.Now()
				expiry := now.Add(1 * time.Hour)
				return &oid4vci.CredentialResponse{
					Credential: buildTestJWTWithExpiry(now, expiry),
					Format:     "jwt_vc_json",
				}, nil
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(capturedReq.CredentialConfigurationID).To(Equal(credType))
			Expect(capturedReq.Format).To(Equal("jwt_vc_json"))
			Expect(capturedURL).To(Equal("https://issuer.example.com/credentials"))
			Expect(capturedToken).To(Equal("test-access-token"))
		})
	})

	Context("custom renewBefore duration", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)

			// Create VCRequest with custom renewBefore = 30 minutes.
			renewBefore := metav1.Duration{Duration: 30 * time.Minute}
			vcReq := &vcv1alpha1.VerifiableCredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vcReqName,
					Namespace: vcReqNs,
				},
				Spec: vcv1alpha1.VerifiableCredentialRequestSpec{
					IssuerRef:      vcv1alpha1.LocalObjectReference{Name: issuerName},
					CredentialType: credType,
					Format:         "jwt_vc_json",
					TargetSecretRef: vcv1alpha1.TargetSecretReference{
						Name: targetSecret,
						Key:  "credential",
					},
					RenewBefore: &renewBefore,
				},
			}
			Expect(k8sClient.Create(ctx, vcReq)).To(Succeed())

			setupHappyPath()
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should requeue earlier based on custom renewBefore", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// Expiry in 1 hour, renewBefore 30 minutes → requeue in ~30 minutes.
			Expect(result.RequeueAfter).To(BeNumerically(">", 25*time.Minute))
			Expect(result.RequeueAfter).To(BeNumerically("<", 35*time.Minute))
		})
	})
})

var _ = Describe("resolveFormat", func() {
	var reconciler *VerifiableCredentialRequestReconciler

	BeforeEach(func() {
		reconciler = &VerifiableCredentialRequestReconciler{}
	})

	It("should return the spec format when specified", func() {
		Expect(reconciler.resolveFormat("ldp_vc")).To(Equal("ldp_vc"))
	})

	It("should return the default format when empty", func() {
		Expect(reconciler.resolveFormat("")).To(Equal(vcv1alpha1.DefaultCredentialFormat))
	})
})

var _ = Describe("resolveRenewBefore", func() {
	var reconciler *VerifiableCredentialRequestReconciler

	BeforeEach(func() {
		reconciler = &VerifiableCredentialRequestReconciler{}
	})

	It("should return the spec duration when specified", func() {
		d := metav1.Duration{Duration: 10 * time.Minute}
		Expect(reconciler.resolveRenewBefore(&d)).To(Equal(10 * time.Minute))
	})

	It("should return the default when nil", func() {
		Expect(reconciler.resolveRenewBefore(nil)).To(Equal(credential.DefaultRenewBeforeDuration))
	})
})
