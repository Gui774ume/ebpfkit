/*
Copyright © 2020 GUILLAUME FOURNIER

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

package ebpfkit

import (
	"bytes"
	"time"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/manager"
	"github.com/pkg/errors"

	"github.com/Gui774ume/ebpfkit/pkg/assets"
)

// EBPFKit is the main EBPFKit structure
type EBPFKit struct {
	options   Options
	startTime time.Time

	httpPatterns   *ebpf.Map
	manager        *manager.Manager
	managerOptions manager.Options
}

// New creates a new EBPFKit instance
func New(options Options) *EBPFKit {
	return &EBPFKit{
		options: options,
	}
}

// Start initializes and start EBPFKit
func (e *EBPFKit) Start() error {
	if err := e.start(); err != nil {
		return err
	}
	return nil
}

func (e *EBPFKit) start() error {
	// fetch ebpf assets
	buf, err := assets.Asset("/probe.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup a default manager
	e.setupDefaultManager()

	// initialize the manager
	if err := e.manager.InitWithOptions(bytes.NewReader(buf), e.managerOptions); err != nil {
		return errors.Wrap(err, "couldn't init manager")
	}

	// setup maps
	if err := e.setupMaps(); err != nil {
		return errors.Wrap(err, "couldn't init eBPF maps")
	}

	// start the manager
	if err := e.manager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start manager")
	}

	e.startTime = time.Now()
	return nil
}

// Stop shuts down EBPFKit
func (e *EBPFKit) Stop() error {
	// Close the manager
	return errors.Wrap(e.manager.Stop(manager.CleanAll), "couldn't stop manager")
}

func (e *EBPFKit) setupMaps() error {
	var err error
	// select maps
	e.httpPatterns, _, err = e.manager.GetMap("http_patterns")
	if err != nil {
		return err
	}
	return nil
}
