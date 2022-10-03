// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/choria-io/aaasvc/auditors (interfaces: Auditor)

// mockgen -package basicjwt -destination mock_auditor_test.go github.com/choria-io/aaasvc/auditors Auditor

// Package basicjwt is a generated GoMock package.
package basicjwt

import (
	reflect "reflect"

	auditors "github.com/choria-io/aaasvc/auditors"
	protocol "github.com/choria-io/go-choria/protocol"
	gomock "github.com/golang/mock/gomock"
)

// MockAuditor is a mock of Auditor interface.
type MockAuditor struct {
	ctrl     *gomock.Controller
	recorder *MockAuditorMockRecorder
}

// MockAuditorMockRecorder is the mock recorder for MockAuditor.
type MockAuditorMockRecorder struct {
	mock *MockAuditor
}

// NewMockAuditor creates a new mock instance.
func NewMockAuditor(ctrl *gomock.Controller) *MockAuditor {
	mock := &MockAuditor{ctrl: ctrl}
	mock.recorder = &MockAuditorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuditor) EXPECT() *MockAuditorMockRecorder {
	return m.recorder
}

// Audit mocks base method.
func (m *MockAuditor) Audit(arg0 auditors.Action, arg1 string, arg2 protocol.Request) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Audit", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// Audit indicates an expected call of Audit.
func (mr *MockAuditorMockRecorder) Audit(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Audit", reflect.TypeOf((*MockAuditor)(nil).Audit), arg0, arg1, arg2)
}
