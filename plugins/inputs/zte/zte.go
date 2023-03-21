package zte

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/plugins/inputs"
)

//go:embed sample.conf
var sampleConfig string

type DataResponse struct {
	Cell_id                    string  `json:"cell_id"`
	Date_month                 int64   `json:"date_month,string"`
	Ecio                       string  `json:"ecio"`
	Hardware_version           string  `json:"hardware_version"`
	Ipv6_wan_ipaddr            string  `json:"ipv6_wan_ipaddr"`
	Loginfo                    string  `json:"loginfo"`
	Lte_ca_pcell_arfcn         string  `json:"lte_ca_pcell_arfcn"`
	Lte_ca_pcell_band          int64   `json:"lte_ca_pcell_band,string"`
	Lte_ca_pcell_bandwidth     float64 `json:"lte_ca_pcell_bandwidth,string"`
	Lte_ca_scell_arfcn         string  `json:"lte_ca_scell_arfcn"`
	Lte_ca_scell_band          int64   `json:"lte_ca_scell_band,string"`
	Lte_ca_scell_bandwidth     float64 `json:"lte_ca_scell_bandwidth,string"`
	Lte_ca_scell_info          string  `json:"lte_ca_scell_info"`
	Lte_multi_ca_scell_info    string  `json:"lte_multi_ca_scell_info"`
	Lte_pci                    string  `json:"lte_pci"`
	Lte_rsrp                   int64   `json:"lte_rsrp,string"`
	Lte_snr                    float64 `json:"lte_snr,string"`
	Wlan_mac_address           string  `json:"wlan_mac_address"`
	Modem_main_state           string  `json:"modem_main_state"`
	Monthly_rx_bytes           int64   `json:"monthly_rx_bytes,string"`
	Monthly_time               int64   `json:"monthly_time,string"`
	Monthly_tx_bytes           int64   `json:"monthly_tx_bytes,string"`
	Network_type               string  `json:"network_type"`
	Nr5g_action_band           string  `json:"nr5g_action_band"`
	Nr5g_action_channel        int64   `json:"nr5g_action_channel,string"`
	Nr5g_cell_id               string  `json:"nr5g_cell_id"`
	Nr5g_pci                   string  `json:"nr5g_pci"`
	Ppp_dial_conn_fail_counter int64   `json:"ppp_dial_conn_fail_counter,string"`
	Ppp_status                 string  `json:"ppp_status"`
	Realtime_rx_bytes          int64   `json:"realtime_rx_bytes,string"`
	Realtime_rx_thrpt          int64   `json:"realtime_rx_thrpt,string"`
	Realtime_time              int64   `json:"realtime_time,string"`
	Realtime_tx_bytes          int64   `json:"realtime_tx_bytes,string"`
	Realtime_tx_thrpt          int64   `json:"realtime_tx_thrpt,string"`
	Rscp                       string  `json:"rscp"`
	Rssi                       string  `json:"rssi"`
	Signalbar                  int64   `json:"signalbar,string"`
	Wan_active_band            string  `json:"wan_active_band"`
	Wan_active_channel         int64   `json:"wan_active_channel,string"`
	Wan_ipaddr                 string  `json:"wan_ipaddr"`
	Wan_lte_ca                 string  `json:"wan_lte_ca"`
	Wa_inner_version           string  `json:"wa_inner_version"`
	Web_version                string  `json:"web_version"`
	Z5g_CELL_ID                string  `json:"Z5g_CELL_ID"`
	Z5g_dlEarfcn               string  `json:"Z5g_dlEarfcn"`
	Z5g_rsrp                   int64   `json:"Z5g_rsrp,string"`
	Z5g_SINR                   float64 `json:"Z5g_SINR,string"`
	Z5g_SNR                    string  `json:"Z5g_SNR"`
	ZCELLINFO_band             string  `json:"ZCELLINFO_band"`
}

type Zte struct {
	RouterUrl           string          `toml:"router_url"`
	LoginPasswordSha256 string          `toml:"login_password_sha256"`
	Timeout             config.Duration `toml:"timeout"`

	Log telegraf.Logger `toml:"-"`

	parsedUrl    *url.URL
	cachedClient *http.Client
}

type LoginResponse struct {
	Result int64 `json:",string"`
}

type LdResponse struct {
	LD string
}

func (*Zte) SampleConfig() string {
	return sampleConfig
}

func (s *Zte) cmdGet(cmd string, data url.Values, out interface{}) error {
	if data == nil {
		data = s.parsedUrl.Query()
	}
	data.Set("isTest", "false")
	data.Set("cmd", cmd)

	ref := s.parsedUrl.ResolveReference(&url.URL{Path: path.Join(s.parsedUrl.Path, "goform_get_cmd_process"), RawQuery: data.Encode()})
	s.Log.Debug("GET ", ref)
	req, err := http.NewRequest(http.MethodGet, ref.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Add("Referer", s.parsedUrl.String())

	res, err := s.cachedClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	s.Log.Debug("JSON ", string(resBody))
	err = json.Unmarshal(resBody, &out)
	if err != nil {
		return err
	}

	return nil
}

func (s *Zte) cmdSet(goformId string, data url.Values, out interface{}) error {
	if data == nil {
		data = s.parsedUrl.Query()
	}
	data.Set("isTest", "false")
	data.Set("goformId", goformId)

	ref := s.parsedUrl.ResolveReference(&url.URL{Path: path.Join(s.parsedUrl.Path, "goform_set_cmd_process")})
	s.Log.Debugf("POST %s (%s)", ref, data.Encode())
	req, err := http.NewRequest(http.MethodPost, ref.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Referer", s.parsedUrl.String())
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := s.cachedClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	s.Log.Debug("JSON ", string(resBody))
	err = json.Unmarshal(resBody, &out)
	if err != nil {
		return err
	}

	return nil
}

func (s *Zte) login(ld string) (int64, error) {
	var lr LoginResponse
	data := url.Values{}

	h := sha256.New()
	h.Write([]byte(s.LoginPasswordSha256 + ld))
	data.Set("password", strings.ToUpper(hex.EncodeToString(h.Sum(nil))))

	err := s.cmdSet("LOGIN", data, &lr)
	if err != nil {
		return -1, err
	}

	return lr.Result, nil
}

func (s *Zte) getLd() (string, error) {
	var ld LdResponse
	err := s.cmdGet("LD", nil, &ld)
	if err != nil {
		return "", err
	}

	s.Log.Debugf("LD: %s\n", ld.LD)
	return ld.LD, nil
}

func (s *Zte) authenticate() error {
	s.Log.Debug("Start Authentication")

	ld, err := s.getLd()
	if err != nil {
		return err
	}

	res, err := s.login(ld)
	if err != nil {
		return err
	}

	if res != 0 {
		return fmt.Errorf("Login Error: %d", res)
	}
	return nil
}

func (s *Zte) Init() error {
	var err error
	s.parsedUrl, err = url.Parse(s.RouterUrl)
	if err != nil {
		return err
	}

	if s.parsedUrl.Scheme != "http" {
		s.parsedUrl = &url.URL{Scheme: "http", Host: "192.168.1.1:80"}
		s.Log.Warnf("Invalid Router URL, using Default: %s://%s", s.parsedUrl.Scheme, s.parsedUrl.Host)
	}
	s.parsedUrl.Path = "/goform"
	s.Log.Debug("Target: ", s.parsedUrl)

	if s.Timeout < config.Duration(time.Second) {
		s.Timeout = config.Duration(time.Second * 5)
	}

	if s.cachedClient == nil {
		transport := &http.Transport{
			ResponseHeaderTimeout: time.Duration(s.Timeout),
		}
		jar, err := cookiejar.New(nil)
		if err != nil {
			return err
		}
		s.cachedClient = &http.Client{
			Transport: transport,
			Jar:       jar,
			Timeout:   time.Duration(s.Timeout),
		}
	}

	return nil
}

func (s *Zte) Gather(acc telegraf.Accumulator) error {
	err := s.authenticate()
	if err != nil {
		return err
	}

	s.Log.Debug("Request Data")
	data := s.parsedUrl.Query()
	data.Set("multi_data", "1")

	var dr DataResponse
	drtype := reflect.TypeOf(dr)
	keys := make([]string, drtype.NumField())
	for i := range keys {
		keys[i] = strings.Split(drtype.Field(i).Tag.Get("json"), ",")[0]
	}

	err = s.cmdGet(strings.Join(keys[:], ","), data, &dr)
	if err != nil {
		return err
	}

	tags := map[string]string{
		"hostname":         s.parsedUrl.Hostname(),
		"port":             s.parsedUrl.Port(),
		"wlan_mac_address": dr.Wlan_mac_address,
	}

	v := reflect.ValueOf(dr)
	ar := make(map[string]interface{}, v.NumField())
	for i := range keys {
		ar[v.Type().Field(i).Name] = v.Field(i).Interface()
	}

	acc.AddFields("zte", ar, tags)

	return nil
}

func init() {
	inputs.Add("zte", func() telegraf.Input { return &Zte{} })
}
