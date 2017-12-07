package main

import (
	"net/http"
	"fmt"
	"github.com/lvfeiyang/proxy/common/flog"
	"io/ioutil"
	"encoding/json"
	"net/url"
	"time"
	"math/rand"
	"sort"
	"strconv"
	"crypto/sha1"
	"crypto/hmac"
	"encoding/base64"
)

func main() {
	flog.Init()
	//获取公网IP
	// pubIp := publicIp()
	// fmt.Println(pubIp)

	//与阿里现有记录比较
	now := time.Now()

	//公共参数
	sigNonce := rand.New(rand.NewSource(now.UnixNano())).Uint64()
	commonUrl := "https://alidns.aliyuncs.com/?Format=JSON&Version=2015-01-09"+
		"&AccessKeyId=LTAIobDblqoBfA4s&SignatureMethod=HMAC-SHA1"+
		"&Timestamp="+now.UTC().Format(time.RFC3339)+"&SignatureVersion=1.0"+
		"&SignatureNonce="+strconv.FormatUint(sigNonce, 10)
	u, _ := url.Parse(commonUrl)
	q := u.Query()
	//获取解析列表 参数
	q.Set("Action", "DescribeDomainRecords")

	sign := signAlg(q)
	q.Set("Signature", sign)
	u.RawQuery = q.Encode()

	//添加或修改dns解析
}

//签名算法
func signAlg(q url.Values) string {
	// q := u.Query()
	keys := make([]string, len(q))
	var i int
	var signstr string //"GET&/&"
	for k, _ := range q {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	for _, k := range keys {
		signstr += k+"="+q.Get(k)+"&"
	}
	signstr = "GET&%2F&"+url.QueryEscape(signstr[:len(signstr)-1])
	fmt.Println(signstr)
	mac := hmac.New(sha1.New, []byte("4405TzYgX6ROxLkBXh2LFHXpe6Y8Tm&"))
	mac.Write([]byte(signstr))
	sign := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(sign)
}

type ipInfo struct {
	Ip string `json:"ip"`
}
func publicIp() string {
	req, _ := http.NewRequest("GET", "http://ipinfo.io", nil);
	req.Header.Set("Accept", "application/json")
	// req.Header.Set("User-Agent", "curl/7.47.0")
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		flog.LogFile.Println(err)
	}
	defer rsp.Body.Close()
	body, err := ioutil.ReadAll(rsp.Body)
	ip := &ipInfo{}
	if err := json.Unmarshal(body, ip); err != nil {
		flog.LogFile.Println(err)
	}
	return ip.Ip
}
