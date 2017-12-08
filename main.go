package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/lvfeiyang/proxy/common/flog"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

type domainRecordsRsp struct {
	Code          string `json:",omitempty"`
	Message       string `json:",omitempty"`
	RequestId     string
	DomainRecords struct {
		Record []struct {
			RecordId string
			RR       string
			Type     string
			Value    string
		}
	} `json:",omitempty"`
}
type updateRecordRsp struct {
	Code      string `json:",omitempty"`
	Message   string `json:",omitempty"`
	RequestId string
	RecordId  string
}

func main() {
	flog.Init()
	//获取公网IP
	pubIp := publicIp()
	// fmt.Println(pubIp)

	//与阿里现有记录比较
	domList := getDomainRecords("home")
	// fmt.Println(domList)

	if "" != domList.Code {
		flog.LogFile.Println("Code:", domList.Code, "Message:", domList.Message)
	} else {
		updateRsp := &updateRecordRsp{}
		if len(domList.DomainRecords.Record) > 0 {
			if domList.DomainRecords.Record[0].Value == pubIp {
				//已存在且相等 不操作
			} else {
				//修改dns解析
				updateRsp = updateRecord(pubIp, domList.DomainRecords.Record[0].RecordId)
			}
		} else {
			//添加dns解析
			updateRsp = updateRecord(pubIp, "")
		}
		if "" != updateRsp.Code {
			flog.LogFile.Println("Code:", updateRsp.Code, "Message:", updateRsp.Message)
		}
	}
	fmt.Println("finish")
}

func updateRecord(v, id string) *updateRecordRsp {
	commonUrl := asseCommonUrl()
	u, _ := url.Parse(commonUrl)
	q := u.Query()
	if "" == id {
		q.Set("Action", "AddDomainRecord")
		q.Set("DomainName", "leonzero.top")
	} else {
		q.Set("Action", "UpdateDomainRecord")
		q.Set("RecordId", id)
	}
	q.Set("RR", "home")
	q.Set("Type", "A")
	q.Set("Value", v)

	sign := signAlg(q)
	q.Set("Signature", sign)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", "", nil)
	recordErr(err)
	req.URL = u
	rsp, err := http.DefaultClient.Do(req)
	recordErr(err)
	defer rsp.Body.Close()
	rspBodyj, err := ioutil.ReadAll(rsp.Body)
	recordErr(err)

	rspBody := &updateRecordRsp{}
	if err := json.Unmarshal(rspBodyj, rspBody); err != nil {
		flog.LogFile.Println(err)
	}
	return rspBody
}

//获取现在的解析记录
func getDomainRecords(rr string) *domainRecordsRsp {
	commonUrl := asseCommonUrl()
	u, _ := url.Parse(commonUrl)
	q := u.Query()
	//获取解析列表 参数
	q.Set("Action", "DescribeDomainRecords")
	q.Set("DomainName", "leonzero.top")
	q.Set("RRKeyWord", rr)
	q.Set("TypeKeyWord", "A")

	sign := signAlg(q)
	q.Set("Signature", sign)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", "", nil)
	recordErr(err)
	req.URL = u
	rsp, err := http.DefaultClient.Do(req)
	recordErr(err)
	defer rsp.Body.Close()
	rspBodyj, err := ioutil.ReadAll(rsp.Body)
	recordErr(err)
	rspBody := &domainRecordsRsp{}
	if err := json.Unmarshal(rspBodyj, rspBody); err != nil {
		flog.LogFile.Println(err)
	}
	return rspBody
}

//公共参数
func asseCommonUrl() string {
	now := time.Now()
	sigNonce := rand.New(rand.NewSource(now.UnixNano())).Uint64()
	commonUrl := "http://alidns.aliyuncs.com/?Format=JSON&Version=2015-01-09" +
		"&AccessKeyId=LTAIobDblqoBfA4s&SignatureMethod=HMAC-SHA1" +
		"&Timestamp=" + now.UTC().Format(time.RFC3339) + "&SignatureVersion=1.0" +
		"&SignatureNonce=" + strconv.FormatUint(sigNonce, 10)
	return commonUrl
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
		signstr += url.QueryEscape(k) + "=" + url.QueryEscape(q.Get(k)) + "&"
	}
	signstr = "GET&%2F&" + url.QueryEscape(signstr[:len(signstr)-1])
	mac := hmac.New(sha1.New, []byte("4405TzYgX6ROxLkBXh2LFHXpe6Y8Tm&"))
	mac.Write([]byte(signstr))
	sign := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(sign)
}

type ipInfo struct {
	Ip string `json:"ip"`
}

func publicIp() string {
	req, _ := http.NewRequest("GET", "http://ipinfo.io", nil)
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

func recordErr(err error) {
	if err != nil {
		flog.LogFile.Println(err)
	}
}
