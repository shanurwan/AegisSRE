package model

import "strings"

type ResourceTarget struct {
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
}

func (t ResourceTarget) Validate() error {
	for field, value := range map[string]string{
		"target.api_version": t.APIVersion, "target.kind": t.Kind,
		"target.namespace": t.Namespace, "target.name": t.Name,
	} {
		if err := requireText(field, value); err != nil {
			return err
		}
	}
	if strings.Contains(t.Namespace, "/") || strings.Contains(t.Name, "/") {
		return NewError(CodeInvalidInput, "resource namespace and name must not contain slashes")
	}
	return nil
}

func (t ResourceTarget) Key() string {
	return t.APIVersion + "/" + t.Kind + "/" + t.Namespace + "/" + t.Name
}

func (t ResourceTarget) Equal(other ResourceTarget) bool {
	return t == other
}
