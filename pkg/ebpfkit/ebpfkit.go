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
	"fmt"
	"log"
	"time"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/manager"
	"github.com/Gui774ume/ebpfkit/pkg/assets"
	"github.com/pkg/errors"
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

func (e *EBPFKit) dumpPrograms() {
	var progIds []int
	prev := 0
	for {
		id, err := ProgGetNextId(prev)
		if err != nil {
			log.Printf("Failed to retrieve prog: %s", err)
			break
		}

		if id == -1 {
			break
		}

		progIds = append(progIds, id)
		prev = id
	}

	fmt.Printf("Programs: %+v\n", progIds)
}

func (e *EBPFKit) start() error {
	// fetch ebpf assets
	buf, err := assets.Asset("/probe.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup the manager
	e.setupManager()

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

	if err := e.setupProgramMaps(); err != nil {
		return errors.Wrap(err, "failed to setup program maps")
	}

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

func (e *EBPFKit) setupProgramMaps() error {
	time.Sleep(time.Second)

	bpfProgMap, _, err := e.manager.GetMap("bpf_programs")
	if err != nil {
		return errors.Wrap(err, "couldn't get bpf program map")
	}

	bpfMapMap, _, err := e.manager.GetMap("bpf_maps")
	if err != nil {
		return errors.Wrap(err, "couldn't get bpf map map")
	}

	bpfNextProgramMap, _, err := e.manager.GetMap("bpf_next_id")
	if err != nil {
		return errors.Wrap(err, "couldn't get bpf_next_id map")
	}

	bpfNextProgramMap.Put(uint32(0), uint32(0xFFFFFFFF)) // next program
	bpfNextProgramMap.Put(uint32(1), uint32(0xFFFFFFFF)) // next map

	for _, probe := range e.manager.Probes {
		progID, err := probe.Program().ID()
		if err != nil {
			log.Printf("Failed to get program id for probe %s", probe.Section)
			continue
		}

		if err := bpfProgMap.Put(uint32(progID), uint32(0xFFFFFFFF)); err != nil {
			return errors.Wrap(err, "failed to insert program into map")
		}
	}

	for _, tailCallRoute := range e.managerOptions.TailCallRouter {
		programs, _, _ := e.manager.GetProgram(tailCallRoute.ProbeIdentificationPair)

		for _, program := range programs {
			progID, err := program.ID()
			if err != nil {
				log.Printf("Failed to get program id for probe %s", program.String())
				continue
			}

			if err := bpfProgMap.Put(uint32(progID), uint32(0xFFFFFFFF)); err != nil {
				return errors.Wrap(err, "failed to insert program into map")
			}
		}
	}

	for _, m := range e.manager.Maps {
		ebpfMap, _, err := e.manager.GetMap(m.Name)
		if err != nil {
			log.Printf("Failed to get map %s", m.Name)
		}

		id, err := ebpfMap.ID()
		if err != nil {
			log.Printf("Failed to get id for map %s", m.Name)
			continue
		}

		if err := bpfMapMap.Put(uint32(id), uint32(0xFFFFFFFF)); err != nil {
			return errors.Wrap(err, "failed to insert map id into map")
		}
	}

	return nil
}
