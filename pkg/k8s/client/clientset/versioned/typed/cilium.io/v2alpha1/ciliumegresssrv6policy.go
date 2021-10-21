// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2021 Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package v2alpha1

import (
	"context"
	"time"

	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	scheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// CiliumEgressSRv6PoliciesGetter has a method to return a CiliumEgressSRv6PolicyInterface.
// A group's client should implement this interface.
type CiliumEgressSRv6PoliciesGetter interface {
	CiliumEgressSRv6Policies() CiliumEgressSRv6PolicyInterface
}

// CiliumEgressSRv6PolicyInterface has methods to work with CiliumEgressSRv6Policy resources.
type CiliumEgressSRv6PolicyInterface interface {
	Create(ctx context.Context, ciliumEgressSRv6Policy *v2alpha1.CiliumEgressSRv6Policy, opts v1.CreateOptions) (*v2alpha1.CiliumEgressSRv6Policy, error)
	Update(ctx context.Context, ciliumEgressSRv6Policy *v2alpha1.CiliumEgressSRv6Policy, opts v1.UpdateOptions) (*v2alpha1.CiliumEgressSRv6Policy, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v2alpha1.CiliumEgressSRv6Policy, error)
	List(ctx context.Context, opts v1.ListOptions) (*v2alpha1.CiliumEgressSRv6PolicyList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2alpha1.CiliumEgressSRv6Policy, err error)
	CiliumEgressSRv6PolicyExpansion
}

// ciliumEgressSRv6Policies implements CiliumEgressSRv6PolicyInterface
type ciliumEgressSRv6Policies struct {
	client rest.Interface
}

// newCiliumEgressSRv6Policies returns a CiliumEgressSRv6Policies
func newCiliumEgressSRv6Policies(c *CiliumV2alpha1Client) *ciliumEgressSRv6Policies {
	return &ciliumEgressSRv6Policies{
		client: c.RESTClient(),
	}
}

// Get takes name of the ciliumEgressSRv6Policy, and returns the corresponding ciliumEgressSRv6Policy object, and an error if there is any.
func (c *ciliumEgressSRv6Policies) Get(ctx context.Context, name string, options v1.GetOptions) (result *v2alpha1.CiliumEgressSRv6Policy, err error) {
	result = &v2alpha1.CiliumEgressSRv6Policy{}
	err = c.client.Get().
		Resource("ciliumegresssrv6policies").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of CiliumEgressSRv6Policies that match those selectors.
func (c *ciliumEgressSRv6Policies) List(ctx context.Context, opts v1.ListOptions) (result *v2alpha1.CiliumEgressSRv6PolicyList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v2alpha1.CiliumEgressSRv6PolicyList{}
	err = c.client.Get().
		Resource("ciliumegresssrv6policies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested ciliumEgressSRv6Policies.
func (c *ciliumEgressSRv6Policies) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("ciliumegresssrv6policies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a ciliumEgressSRv6Policy and creates it.  Returns the server's representation of the ciliumEgressSRv6Policy, and an error, if there is any.
func (c *ciliumEgressSRv6Policies) Create(ctx context.Context, ciliumEgressSRv6Policy *v2alpha1.CiliumEgressSRv6Policy, opts v1.CreateOptions) (result *v2alpha1.CiliumEgressSRv6Policy, err error) {
	result = &v2alpha1.CiliumEgressSRv6Policy{}
	err = c.client.Post().
		Resource("ciliumegresssrv6policies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(ciliumEgressSRv6Policy).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a ciliumEgressSRv6Policy and updates it. Returns the server's representation of the ciliumEgressSRv6Policy, and an error, if there is any.
func (c *ciliumEgressSRv6Policies) Update(ctx context.Context, ciliumEgressSRv6Policy *v2alpha1.CiliumEgressSRv6Policy, opts v1.UpdateOptions) (result *v2alpha1.CiliumEgressSRv6Policy, err error) {
	result = &v2alpha1.CiliumEgressSRv6Policy{}
	err = c.client.Put().
		Resource("ciliumegresssrv6policies").
		Name(ciliumEgressSRv6Policy.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(ciliumEgressSRv6Policy).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the ciliumEgressSRv6Policy and deletes it. Returns an error if one occurs.
func (c *ciliumEgressSRv6Policies) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("ciliumegresssrv6policies").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *ciliumEgressSRv6Policies) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("ciliumegresssrv6policies").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched ciliumEgressSRv6Policy.
func (c *ciliumEgressSRv6Policies) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2alpha1.CiliumEgressSRv6Policy, err error) {
	result = &v2alpha1.CiliumEgressSRv6Policy{}
	err = c.client.Patch(pt).
		Resource("ciliumegresssrv6policies").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
