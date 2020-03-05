package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"strings"

	"github.com/yl2chen/cidranger"

	"github.com/miekg/dns"

	"gopkg.in/yaml.v2"
)

type RawConfig struct {
	Networks []struct {
		CIDR  string            `yaml:"cidr"`
		Rules map[string]string `yaml:"rules"`
	} `yaml:"networks"`
	DefaultAdapter string `yaml:"adapter,omitempty"`
	Port           int    `yaml:"port,omitempty"`
	Proto          string `yaml:"protocol,omitempty"`
}

type Network struct {
	Ranger cidranger.Ranger
	Rules  map[string]string
}

type Config struct {
	Networks       []Network
	DefaultAdapter string
	Nolog          bool
}

type Cache map[string](map[string]dns.RR)

var dnsCache = Cache{}
var config = Config{}

func panicIfErr(e error) {
	if e != nil {
		panic(e)
	}
}

func logIfErr(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func getIPAddress(config Config) (*net.IP, error) {
	ifaces, err := net.Interfaces()
	panicIfErr(err)
	for _, i := range ifaces {
		if config.DefaultAdapter != "" && config.DefaultAdapter != i.Name {
			continue
		}

		addrs, err := i.Addrs()
		panicIfErr(err)
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.IP.To4() != nil {
					return &v.IP, nil
				}
			case *net.IPAddr:
				if v.IP.To4() != nil {
					return &v.IP, nil
				}
			}
		}
	}
	return nil, errors.New("Should not reach here")
}

func parseQuery(m *dns.Msg, config Config) {
	ip, err := getIPAddress(config)
	panicIfErr(err)
	ipStr := ip.String()
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			if dnsCache[ipStr] != nil && dnsCache[ipStr][q.Name] != nil {
				m.Answer = append(m.Answer, dnsCache[ipStr][q.Name])
				if !config.Nolog {
					log.Printf("[%s] %s\n", ipStr, dnsCache[ipStr][q.Name].String())
				}
				continue
			}
			hit := false
			for _, network := range config.Networks {
				contains, err := network.Ranger.Contains(*ip)
				panicIfErr(err)
				if contains && network.Rules[q.Name] != "" {
					ip := network.Rules[q.Name]
					recordType := "A"
					if strings.Contains(ip, ":") {
						recordType = "AAAA"
					}
					rr, err := dns.NewRR(fmt.Sprintf("%s %s %s", q.Name, recordType, ip))
					panicIfErr(err)
					m.Answer = append(m.Answer, rr)
					if !config.Nolog {
						log.Printf("[%s] %s\n", ipStr, rr.String())
					}
					if dnsCache[ipStr] == nil {
						dnsCache[ipStr] = map[string]dns.RR{}
					}
					dnsCache[ipStr][q.Name] = rr
					hit = true
					break
				}
			}
			if !hit {
				ips, err := net.LookupIP(q.Name)
				panicIfErr(err)
				for _, ip := range ips {
					recordType := "A"
					if ip.To4() == nil {
						recordType = "AAAA"
					}
					rr, err := dns.NewRR(fmt.Sprintf("%s %s %s", q.Name, recordType, ip))
					panicIfErr(err)
					m.Answer = append(m.Answer, rr)
					if !config.Nolog {
						log.Printf("[%s] %s\n", ipStr, rr.String())
					}
				}
			}
		}
	}
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m, config)
	}

	w.WriteMsg(m)
}

func main() {
	homeDir, err := os.UserHomeDir()
	panicIfErr(err)
	defaultConfigPath := path.Join(homeDir, ".config", "selective-dns-query.yml")
	configPath := flag.String("config", defaultConfigPath, "Path for config file")
	nolog := flag.Bool("quiet", false, "If specified, do not print query log")
	flag.Parse()

	dat, err := ioutil.ReadFile(*configPath)
	panicIfErr(err)
	rawConfig := RawConfig{}
	panicIfErr(yaml.Unmarshal(dat, &rawConfig))

	_config := Config{DefaultAdapter: rawConfig.DefaultAdapter, Nolog: *nolog}
	for _, network := range rawConfig.Networks {
		ranger := cidranger.NewPCTrieRanger()
		_, cidr, _ := net.ParseCIDR(network.CIDR)
		ranger.Insert(cidranger.NewBasicRangerEntry(*cidr))
		rules := map[string]string{}
		for domain, ip := range network.Rules {
			if strings.HasSuffix(domain, ".") {
				rules[domain] = ip
			} else {
				rules[domain+"."] = ip
			}
		}
		_config.Networks = append(config.Networks, Network{Ranger: ranger, Rules: rules})
	}
	config = _config

	listenPort := 53
	net := "udp"
	if rawConfig.Port != 0 {
		listenPort = rawConfig.Port
	}
	if rawConfig.Proto != "" {
		net = rawConfig.Proto
	}
	log.Printf("Server listening at port %d with protocol %s\n", listenPort, net)
	server := &dns.Server{Addr: fmt.Sprintf(":%d", listenPort), Net: net}
	dns.HandleFunc(".", handleDNSRequest)
	panicIfErr(server.ListenAndServe())
	defer server.Shutdown()
}
