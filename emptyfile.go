/*
Copyright 2019 Adevinta
*/

package gozuul

import "strings"

type strFile struct {
	*strings.Reader
}

func newStrFile(contents string) *strFile {
	return &strFile{strings.NewReader(contents)}
}

func (f *strFile) Close() error {
	return nil
}
