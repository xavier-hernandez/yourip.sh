package main

import (
	"fmt"
	"github.com/oschwald/maxminddb-golang"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	json "github.com/json-iterator/go"

	"github.com/gin-gonic/gin"
	proxyproto "github.com/pires/go-proxyproto"
)

type Configuration struct {
	hostname              string // Displayed Hostname
	cmd_hostname          string // Displayed Hostname for CMD section
	host                  string // Listened Host
	port                  string // HTTP Port
	proxy_listener        string // Proxy Protocol Listener
	ipheader              string // Header to overwrite the remote IP
	countryheader         string // Header to find country code associated to remote IP
	tls                   bool   // TLS enabled
	tlscert               string // TLS Cert Path
	tlskey                string // TLS Cert Key Path
	tlsport               string // HTTPS Port
	maxMindUserName       string // MaxMind UserName
	maxMindPassword       string // MaxMind Password
	plausible             string // Plausible domain
	self_hosted_plausible string // Plausible self hosted domain for JS
}

var configuration = Configuration{}

func init() {
	hostname := getEnvWithDefault("HOSTNAME", "miip.io")
	protocol := getEnvWithDefault("CMD_PROTOCOL", "")

	cmd_hostname := protocol + hostname

	host := getEnvWithDefault("HOST", "")
	port := getEnvWithDefault("PORT", "8080")
	proxy_listener := getEnvWithDefault("PROXY_PROTOCOL_ADDR", "")

	// Most common alternative would be X-Forwarded-For
	ipheader := getEnvWithDefault("FORWARD_IP_HEADER", "CF-Connecting-IP")

	countryheader := getEnvWithDefault("COUNTRY_CODE_HEADER", "CF-IPCountry")

	tlsenabled := getEnvWithDefault("TLS", "0")
	tlsport := getEnvWithDefault("TLSPORT", "8443")
	tlscert := getEnvWithDefault("TLSCERT", "/opt/ifconfig/.cf/ifconfig.io.crt")
	tlskey := getEnvWithDefault("TLSKEY", "/opt/ifconfig/.cf/ifconfig.io.key")

	maxMindUserName := getEnvWithDefault("MAXMIND_USERNAME", "")
	maxMindPassword := getEnvWithDefault("MAXMIND_PASSWORD", "")

	plausible := getEnvWithDefault("PLAUSIBLE", "")
	self_hosted_plausible := getEnvWithDefault("PLAUSIBLE_SELF_HOSTED_DOMAIN", "")

	configuration = Configuration{
		hostname:              hostname,
		cmd_hostname:          cmd_hostname,
		host:                  host,
		port:                  port,
		proxy_listener:        proxy_listener,
		ipheader:              ipheader,
		countryheader:         countryheader,
		tls:                   tlsenabled == "1",
		tlscert:               tlscert,
		tlskey:                tlskey,
		tlsport:               tlsport,
		maxMindUserName:       maxMindUserName,
		maxMindPassword:       maxMindPassword,
		plausible:             plausible,
		self_hosted_plausible: self_hosted_plausible,
	}
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func testRemoteTCPPort(address string) bool {
	_, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return false
	}
	return true
}

func mainHandler(c *gin.Context) {
	// fields := strings.Split(c.Params.ByName("field"), ".")
	URLFields := strings.Split(strings.Trim(c.Request.URL.EscapedPath(), "/"), "/")
	fields := strings.Split(URLFields[0], ".")
	ip, err := net.ResolveTCPAddr("tcp", c.Request.RemoteAddr)
	if err != nil {
		c.Abort()
	}

	header_ip := net.ParseIP(strings.Split(c.Request.Header.Get(configuration.ipheader), ",")[0])
	if header_ip != nil {
		ip.IP = header_ip
	}

	if fields[0] == "porttest" {
		if len(fields) >= 2 {
			if port, err := strconv.Atoi(fields[1]); err == nil && port > 0 && port <= 65535 {
				c.String(200, fmt.Sprintln(testRemoteTCPPort(ip.IP.String()+":"+fields[1])))
			} else {
				c.String(400, "Invalid Port Number")
			}
		} else {
			c.String(400, "Need Port")
		}
		return
	}

	//if strings.HasPrefix(fields[0], ".well-known/") {
	//	http.ServeFile(c.Writer, c.Request)
	//	return
	//}

	c.Set("ifconfig_hostname", configuration.hostname)
	c.Set("ifconfig_cmd_hostname", configuration.cmd_hostname)
	c.Set("ifconfig_plausible", configuration.plausible)
	c.Set("ifconfig_self_hosted_plausible", configuration.self_hosted_plausible)

	t := time.Now()
	c.Set("ifconfig_copyrightYear", t.Year())

	ua := c.Request.UserAgent()

	c.Set("ip", ip.IP.String())
	c.Set("port", ip.Port)
	c.Set("ua", ua)
	c.Set("lang", c.Request.Header.Get("Accept-Language"))
	c.Set("encoding", c.Request.Header.Get("Accept-Encoding"))
	c.Set("method", c.Request.Method)
	c.Set("mime", c.Request.Header.Get("Accept"))
	c.Set("referer", c.Request.Header.Get("Referer"))
	c.Set("forwarded", c.Request.Header.Get("X-Forwarded-For"))
	c.Set("country_code", c.Request.Header.Get(configuration.countryheader))
	c.Set("host", ip.IP.String())

	//MaxMind Logic
	if len(configuration.maxMindUserName) == 0 || len(configuration.maxMindUserName) == 0 {
		//c.Set("maxMindShow", false)
		c.Set("maxMindShow", true)
		maxMindResult := GetMaxMindInfoFromDBs(ip.IP.String())
		if maxMindResult.MaxMindError == false {
			c.Set("city", maxMindResult.City.Names.English)
			c.Set("postalCode", maxMindResult.Postal.Code)
			c.Set("country", maxMindResult.Country.Names.English)
			c.Set("continent", maxMindResult.Continent.Names.English)
			c.Set("isp", maxMindResult.Traits.Isp)
			c.Set("isp_organization", maxMindResult.Traits.Organization)
		} else {
			c.Set("maxMindShow", false)
		}
	} else {
		c.Set("maxMindShow", true)
		maxMindResult := GetMaxMindInfo(ip.IP.String(), configuration.maxMindUserName, configuration.maxMindPassword)
		if maxMindResult.MaxMindError == false {
			c.Set("city", maxMindResult.City.Names.English)
			c.Set("postalCode", maxMindResult.Postal.Code)
			c.Set("country", maxMindResult.Country.Names.English)
			c.Set("continent", maxMindResult.Continent.Names.English)
			c.Set("isp", maxMindResult.Traits.Isp)
			c.Set("isp_organization", maxMindResult.Traits.Organization)
		} else {
			c.Set("maxMindShow", false)
		}
	}

	// Only lookup hostname if the results are going to need it.
	// if stringInSlice(fields[0], []string{"all", "host"}) || (fields[0] == "" && ua[0] != "curl") {
	if fields[0] == "host" || (fields[0] == "" && !isReqFromCmdLine(ua)) {
		hostnames, err := net.LookupAddr(ip.IP.String())
		if err == nil {
			c.Set("host", hostnames[0])
		}
	}

	wantsJSON := len(fields) >= 2 && fields[1] == "json"
	wantsJS := len(fields) >= 2 && fields[1] == "js"

	switch fields[0] {
	case "":
		// If the user is using a command line agent like curl/HTTPie,
		// then we should just return the IP, else we show the home page.
		if isReqFromCmdLine(ua) {
			c.String(200, fmt.Sprintln(ip.IP))
		} else {
			c.HTML(200, "index.html", c.Keys)
		}
		return
	case "request":
		c.JSON(200, c.Request)
		return
	case "all":
		if wantsJSON {
			c.JSON(200, c.Keys)
		} else if wantsJS {
			c.Writer.Header().Set("Content-Type", "application/javascript")
			response, _ := json.Marshal(c.Keys)
			c.String(200, "ifconfig_io = %v\n", string(response))
		} else {
			c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			c.YAML(200, c.Keys)
		}
		return
	case "headers":
		if wantsJS {
			c.Writer.Header().Set("Content-Type", "application/javascript")
			response, _ := json.Marshal(c.Request.Header)
			c.String(200, "ifconfig_io = %v\n", string(response))
		} else {
			c.JSON(200, c.Request.Header)
		}
		return
	}
	fieldResult, exists := c.Get(fields[0])
	if !exists {
		c.String(404, "Not Found")
		return
	}
	if wantsJSON {
		c.JSON(200, fieldResult)
	} else if wantsJS {
		c.Writer.Header().Set("Content-Type", "application/javascript")
		response, _ := json.Marshal(fieldResult)
		c.String(200, "%v = %v\n", fields[0], string(response))
	} else {
		c.String(200, fmt.Sprintln(fieldResult))
	}

}

func getEnvWithDefault(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func main() {
	r := gin.New()
	r.Use(gin.Recovery())
	r.LoadHTMLGlob("templates/*")

	for _, route := range []string{
		"ip", "ua", "port", "lang", "encoding", "method",
		"mime", "referer", "forwarded", "country_code",
		"all", "headers", "porttest", "host",
	} {
		r.GET(fmt.Sprintf("/%s", route), mainHandler)
		r.GET(fmt.Sprintf("/%s.json", route), mainHandler)
		r.GET(fmt.Sprintf("/%s.js", route), mainHandler)
	}
	r.GET("/", mainHandler)

	errc := make(chan error)
	go func(errc chan error) {
		for err := range errc {
			panic(err)
		}
	}(errc)

	go func(errc chan error) {
		errc <- r.Run(fmt.Sprintf("%s:%s", configuration.host, configuration.port))
	}(errc)

	if configuration.tls {
		go func(errc chan error) {
			errc <- r.RunTLS(
				fmt.Sprintf("%s:%s", configuration.host, configuration.tlsport),
				configuration.tlscert, configuration.tlskey)
		}(errc)
	}

	if configuration.proxy_listener != "" {
		go func(errc chan error) {
			list, err := net.Listen("tcp", configuration.proxy_listener)
			if err != nil {
				errc <- err
				return
			}
			proxyListener := &proxyproto.Listener{Listener: list}
			defer proxyListener.Close()
			errc <- r.RunListener(proxyListener)
		}(errc)
	}

	fmt.Println(<-errc)
}

func isReqFromCmdLine(ua string) bool {

	// Example User Agents
	// curl/7.83.1
	// Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.19044; en-US) PowerShell/7.2.4

	// In the case of powershell, we have to look at only the last segment.
	// We could fully parse the user agent, but that would create a lot of garbage.
	// We simply look at the last word.
	// A micro optimization would be to do the search in reverse and break on first match, but
	// I find that harder to read.
	lastSpaceIndex := 0
	for i, c := range ua {
		// Protect if the space is the very last symbol.
		if i == len(ua)-1 {
			break
		}
		if string(c) == " " {
			lastSpaceIndex = i + 1
		}
	}
	ua = ua[lastSpaceIndex:]

	parts := strings.SplitN(ua, "/", 2)
	switch parts[0] {
	case "curl", "HTTPie", "httpie-go", "Wget", "fetch libfetch", "Go", "Go-http-client", "ddclient", "Mikrotik", "xh", "WindowsPowerShell", "PowerShell":
		return true
	}
	return false
}

// MAXMIND
type MaxmindNode struct {
	City struct {
		Names struct {
			English string `json:"en"`
		}
	}
	Continent struct {
		Names struct {
			English string `json:"en"`
		}
	}
	Country struct {
		Names struct {
			English string `json:"en"`
		}
	}
	Location struct {
		AccuracyRadius int32   `json:"accuracy_radius"`
		Latitude       float32 `json:"latitude"`
		Longitude      float32 `json:"longitude"`
		MetroCode      int32   `json:"metro_code"`
		TimeZone       string  `json:"time_zone"`
	} `json:"location"`
	Postal struct {
		Code string `json:"code"`
	} `json:"postal"`
	Traits struct {
		Isp          string `json:"isp"`
		Organization string `json:"organization"`
	}
	MaxMindError bool
}

func GetMaxMindInfo(ipAddress string, username string, password string) MaxmindNode {
	var maxmindResult MaxmindNode

	client := &http.Client{
		//	Transport: &http.Transport{
		//		TLSClientConfig: &tls.Config{
		//			InsecureSkipVerify: true,
		//			//MinVersion: tls.VersionTLS12,
		//		},
		//	},
	}

	apiURL := fmt.Sprintf("https://geoip.maxmind.com/geoip/v2.1/city/%s?pretty", ipAddress)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		maxmindResult.MaxMindError = true
		log.Println(err.Error())
		return maxmindResult
	}
	req.SetBasicAuth(username, password)

	resp, err := client.Do(req)
	if err != nil {
		maxmindResult.MaxMindError = true
		log.Println(err.Error())
		return maxmindResult
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		maxmindResult.MaxMindError = true
		log.Println(fmt.Sprintf("MaxMind - HTTP Error: %s", resp.Status))
		return maxmindResult
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		maxmindResult.MaxMindError = true
		log.Println(fmt.Sprintf("MaxMind - Error reading response"))
		return maxmindResult
	}

	errUnmarshal := json.Unmarshal([]byte(body), &maxmindResult)
	if errUnmarshal != nil {
		maxmindResult.MaxMindError = true
		log.Println(fmt.Sprintf("MaxMind - Error unmarshalling"))
		return maxmindResult
	}

	maxmindResult.MaxMindError = false

	return maxmindResult
}

func GetMaxMindInfoFromDBs(ipAddress string) MaxmindNode {
	var maxmindResult MaxmindNode

	//GET GEO INFO
	var record struct {
		Continent struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"continent"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Subdivisions []struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"subdivisions"`
		Country struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
		Postal struct {
			Code string `maxminddb:"code"`
		} `maxminddb:"postal"`
	}

	db, err := maxminddb.Open("assests/maxmind/GeoLite2-City.mmdb")
	if err != nil {
		maxmindResult.MaxMindError = true
		log.Println(fmt.Sprintf("MaxMind - Cannot find GeoLite2-City.mmdb"))
		return maxmindResult
	}
	defer db.Close()

	ip := net.ParseIP(ipAddress)

	if err := db.Lookup(ip, &record); err != nil {
		log.Println(fmt.Sprintf("MaxMind - Error reading response"))
		log.Panic(err)
		return maxmindResult
	}

	maxmindResult.Continent.Names.English = record.Continent.Names["en"]
	maxmindResult.Postal.Code = record.Postal.Code
	maxmindResult.City.Names.English = record.City.Names["en"]
	maxmindResult.Country.Names.English = record.Country.Names["en"]

	dbASN, err := maxminddb.Open("assests/maxmind/GeoLite2-ASN.mmdb") // Path to your GeoLite2-ASN.mmdb file
	if err != nil {
		log.Println(fmt.Sprintf("MaxMind - Cannot find GeoLite2-ASN.mmdb"))
		return maxmindResult
	}
	defer dbASN.Close()

	var recordASN struct {
		ISP             int    `maxminddb:"autonomous_system_number"`
		ISPOrganization string `maxminddb:"autonomous_system_organization"`
	}

	if err := dbASN.Lookup(ip, &recordASN); err != nil {
		log.Println(fmt.Sprintf("MaxMind - Error reading response"))
		log.Panic(err)
		return maxmindResult
	}

	maxmindResult.Traits.Isp = strconv.Itoa(recordASN.ISP)
	maxmindResult.Traits.Organization = recordASN.ISPOrganization

	maxmindResult.MaxMindError = false

	return maxmindResult
}
