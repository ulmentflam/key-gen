// Package save
/*
Copyright © 2024 Evan Owen <admin@ulmentflam.com>
*/
package save

import (
	"context"

	"key-gen/bip44"
	"key-gen/util"
)

type Saver interface {
	Save(ctx context.Context, config util.KeyConfig, manager *bip44.KeyManager) error
}

type Save struct {
	savers []Saver
	config util.KeyConfig
}

func NewSave(config util.KeyConfig) (*Save, error) {

	var savers []Saver
	if config.OPConfig != nil {
		op, err := NewOPSaver(config)
		if err != nil {
			return nil, err
		}
		savers = append(savers, op)
	}

	fss, err := NewFileSystemSaver(config)
	if err != nil {
		return nil, err
	}
	savers = append(savers, fss)

	return &Save{
		savers,
		config,
	}, nil
}

func (s *Save) Save(ctx context.Context, manager *bip44.KeyManager) error {
	for _, saver := range s.savers {
		err := saver.Save(ctx, s.config, manager)
		if err != nil {
			return err
		}
	}
	return nil
}
