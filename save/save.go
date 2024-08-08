package save

import (
	"context"

	"key-gen/bip44"
	"key-gen/util"
)

type Saver interface {
	Save(ctx context.Context, config util.Config, manager *bip44.KeyManager) error
}

type Save struct {
	savers []Saver
	config util.Config
}

func NewSave(config util.Config) (*Save, error) {

	var savers []Saver
	if config.OPServiceAccountToken != "" {
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

func (s *Save) Save(ctx context.Context, config util.Config, manager *bip44.KeyManager) error {
	for _, saver := range s.savers {
		err := saver.Save(ctx, config, manager)
		if err != nil {
			return err
		}
	}
	return nil
}
