// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package reconciler

import (
	"fmt"
	"strings"
	"time"

	sgv1alpha1 "github.com/vmware-tanzu/carvel-secretgen-controller/pkg/apis/secretgen/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// TerminalReconcileErr represent a reconciliation error that
// cannot be corrected without some change in the system
// (e.g. reconfiguring resources, adding/removing resources).
// It's indicative to not requeue a reconcile request.
type TerminalReconcileErr struct {
	Err error
}

func (e TerminalReconcileErr) Error() string { return e.Err.Error() }

// RequeueReconcileErr represent a reconciliation error that
// should be requeued but without using controller-runtimes
// exponential backoff mechanism. Instead requeue at an interval.
type RequeueReconcileErr struct {
	RequeueAfter time.Duration
	Err          error
}

func (e RequeueReconcileErr) Error() string { return e.Err.Error() }

type Status struct {
	S          sgv1alpha1.GenericStatus
	UpdateFunc func(sgv1alpha1.GenericStatus)
}

func (s *Status) Result() sgv1alpha1.GenericStatus { return s.S }

func (s *Status) IsReconcileSucceeded() bool {
	for _, cond := range s.S.Conditions {
		if cond.Type == sgv1alpha1.ReconcileSucceeded {
			return true
		}
	}
	return false
}

func (s *Status) SetReconciling(meta metav1.ObjectMeta) {
	s.markObservedLatest(meta)
	s.removeAllConditions()

	s.S.Conditions = append(s.S.Conditions, sgv1alpha1.Condition{
		Type:   sgv1alpha1.Reconciling,
		Status: corev1.ConditionTrue,
	})

	s.S.FriendlyDescription = "Reconciling"

	s.UpdateFunc(s.S)
}

func (s *Status) SetReconcileCompleted(err error) {
	s.removeAllConditions()

	if err != nil {
		s.S.Conditions = append(s.S.Conditions, sgv1alpha1.Condition{
			Type:    sgv1alpha1.ReconcileFailed,
			Status:  corev1.ConditionTrue,
			Message: err.Error(),
		})
		s.S.FriendlyDescription = s.friendlyErrMsg(fmt.Sprintf("Reconcile failed: %s", err))
	} else {
		s.S.Conditions = append(s.S.Conditions, sgv1alpha1.Condition{
			Type:    sgv1alpha1.ReconcileSucceeded,
			Status:  corev1.ConditionTrue,
			Message: "",
		})
		s.S.FriendlyDescription = "Reconcile succeeded"
	}

	s.UpdateFunc(s.S)
}

func (s *Status) friendlyErrMsg(errMsg string) string {
	errMsgPieces := strings.Split(errMsg, "\n")
	if len(errMsgPieces[0]) > 80 {
		errMsgPieces[0] = errMsgPieces[0][:80] + "..."
	} else if len(errMsgPieces) > 1 {
		errMsgPieces[0] += "..."
	}
	return errMsgPieces[0]
}

func (s *Status) WithReconcileCompleted(result reconcile.Result, err error) (reconcile.Result, error) {
	s.SetReconcileCompleted(err)
	if err != nil {
		if _, ok := err.(TerminalReconcileErr); ok {
			return reconcile.Result{}, nil
		}
		if requeueErr, ok := err.(RequeueReconcileErr); ok {
			return reconcile.Result{
				RequeueAfter: requeueErr.RequeueAfter + wait.Jitter(time.Second*5, 1.0),
			}, nil
		}
	}
	return result, err
}

func (s *Status) markObservedLatest(meta metav1.ObjectMeta) {
	s.S.ObservedGeneration = meta.Generation
}

func (s *Status) removeAllConditions() {
	s.S.Conditions = nil
}
