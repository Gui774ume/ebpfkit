package network_discovery

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"text/template"

	"github.com/inhies/go-bytesize"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/blake2b"

	"github.com/Gui774ume/ebpfkit/pkg/model"
)

const (
	udpColor = "1"
	tcpColor = "5"
	synColor = "9"
	ackColor = "4"
	rstColor = "9"
	arpColor = "6"
)

type cluster struct {
	ID    string
	Label string
	Nodes map[string]node
}

type node struct {
	ID    string
	Label string
	Size  int
	Color string
}

type edge struct {
	Link  string
	Label string
	Color string
	Style string
}

type graph struct {
	Title string
	Hosts []cluster
	Edges []edge
}

func generateGraph(flows []flow, activeDiscovery bool, passiveDicovery bool) error {
	tmpl := `digraph {
      label     = "{{ .Title }}"
      labelloc  =  "t"
      fontsize  = 75
      fontcolor = "black"
      fontname = "arial"
      nodesep = 2
      sep = "+50"

      graph [pad=2, overlap = false]
	  node [style=rounded, style="rounded", colorscheme=set39, shape=record, fontname = "arial", margin=0.3, padding=1, penwidth=3]
      edge [colorscheme=set39, penwidth=2]

	  {{ range .Hosts }}
	  subgraph {{ .ID }} {
	    label = "{{ .Label }}";
		style = "rounded";
		{{ range .Nodes }}
	    {{ .ID }} [label="{{ .Label }}", fontsize={{ .Size }}, shape=box, color="{{ .Color }}"]{{ end }}
	  }{{ end }}
	
      {{ range .Edges }}
      {{ .Link }} [arrowhead=normal, color="{{ .Color }}", label="{{ .Label }}", fontsize=30, style="{{ .Style }}"]
      {{ end }}
	}
`
	data := prepareGraphData("", flows, activeDiscovery, passiveDicovery)

	f, err := ioutil.TempFile("/tmp", "network-discovery-graph-")
	if err != nil {
		return err
	}
	defer f.Close()

	if err := os.Chmod(f.Name(), os.ModePerm); err != nil {
		return err
	}

	t := template.Must(template.New("tmpl").Parse(tmpl))
	if err := t.Execute(f, data); err != nil {
		return err
	}
	logrus.Infof("Graph generated: %s", f.Name())

	return nil
}

func prepareGraphData(title string, flows []flow, activeDiscovery bool, passiveDicovery bool) graph {
	var i int
	var maxFlowsCount int
	data := graph{
		Title: title,
	}

	// reorder flows by hosts
	hosts := map[string][]int{}
	for _, f := range flows {
		if f.isPassive() && !passiveDicovery || !f.isPassive() && !activeDiscovery {
			continue
		}
		hosts[f.saddr] = append(hosts[f.saddr], int(f.sourcePort))
		hosts[f.daddr] = append(hosts[f.daddr], int(f.destPort))
	}

	ports := map[string][]flow{}
	for _, f := range flows {
		if f.isPassive() && !passiveDicovery || !f.isPassive() && !activeDiscovery {
			continue
		}
		ports[fmt.Sprintf("%s:%d", f.saddr, f.sourcePort)] = append(ports[fmt.Sprintf("%s:%d", f.saddr, f.sourcePort)], f)
		ports[fmt.Sprintf("%s:%d", f.daddr, f.destPort)] = append(ports[fmt.Sprintf("%s:%d", f.daddr, f.destPort)], f)
	}
	for _, fs := range ports {
		if len(fs) > maxFlowsCount {
			maxFlowsCount = len(fs)
		}
	}

	ipToClusterID := map[string]string{}
	for ip, hostPorts := range hosts {
		var label string
		domains, err := net.LookupAddr(ip)
		if err == nil {
			label = ip + "\n[" + strings.Join(domains, ",") + "]"
		} else {
			label = ip
		}
		cls := cluster{
			ID:    fmt.Sprintf("cluster_%d", i),
			Label: label,
			Nodes: make(map[string]node),
		}
		ipToClusterID[ip] = cls.ID
		i++

		for _, port := range hostPorts {
			if port == 0 {
				continue
			}
			n := node{
				ID:    generateNodeID(fmt.Sprintf("%s:%d", ip, port)),
				Label: fmt.Sprintf(":%d", port),
			}
			if port == 0xC001 {
				n.Label = "ebpfkit"
			}

			p := ports[fmt.Sprintf("%s:%d", ip, port)]
			if p[0].udpCount > 0 {
				n.Size = len(p)/maxFlowsCount*40 + 30
				n.Color = udpColor
			}
			if p[0].tcpCount > 0 {
				n.Size = len(p)/maxFlowsCount*40 + 30
				n.Color = tcpColor
			}
			cls.Nodes[generateNodeID(fmt.Sprintf("%s:%d", ip, port))] = n
		}
		data.Hosts = append(data.Hosts, cls)
	}

	for _, f := range flows {
		if f.isPassive() && !passiveDicovery || !f.isPassive() && !activeDiscovery {
			continue
		}
		e := edge{}
		if f.udpCount > 0 {
			e.Label = fmt.Sprintf("%s", bytesize.New(float64(f.udpCount)))
			e.Color = udpColor
		}
		if f.tcpCount > 0 {
			e.Label = fmt.Sprintf("%s", bytesize.New(float64(f.tcpCount)))
			switch f.flowType {
			case model.IngressFlow, model.EgressFlow:
				e.Color = tcpColor
			case model.Syn:
				e.Color = synColor
				e.Style = "dashed"
				e.Label = ""
			case model.Reset:
				e.Color = rstColor
				e.Style = "dashed"
				e.Label = ""
			case model.Ack:
				e.Color = ackColor
				e.Label = ""
			}
		}
		if f.flowType == model.ARPRequest || f.flowType == model.ARPReply {
			if f.flowType == model.ARPRequest {
				e.Label = "ARP Request"
			} else if f.flowType == model.ARPReply {
				e.Label = "ARP Reply"
			}
			e.Color = arpColor
			e.Link = fmt.Sprintf("%s -> %s", ipToClusterID[f.saddr], ipToClusterID[f.daddr])
		}
		if len(e.Link) == 0 {
			e.Link = fmt.Sprintf("%s -> %s", generateNodeID(fmt.Sprintf("%s:%d", f.saddr, f.sourcePort)), generateNodeID(fmt.Sprintf("%s:%d", f.daddr, f.destPort)))
		}
		data.Edges = append(data.Edges, e)
	}
	return data
}

func generateNodeID(section string) string {
	var id string
	for _, b := range blake2b.Sum256([]byte(section)) {
		id += fmt.Sprintf("%v", b)
	}
	return id
}
