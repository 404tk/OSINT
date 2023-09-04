package main

import (
	"flag"
	"fmt"
	"osint/pkg/detectors"
	"osint/pkg/schema"
	"osint/utils/logger"
)

var (
	username string
	cn_uname string
	ip       string
	qq       string
	wb       string
	phone    string
	domain   string
	list     bool
	silent   bool
)

func init() {
	flag.StringVar(&username, "u", "", "Username")
	flag.StringVar(&cn_uname, "cu", "", "Chinese Username")
	flag.StringVar(&ip, "ip", "", "IP")
	flag.StringVar(&qq, "qq", "", "QQ")
	flag.StringVar(&wb, "wb", "", "WB_Uid")
	flag.StringVar(&phone, "ph", "", "Phone number")
	flag.StringVar(&domain, "d", "", "Domain")
	flag.BoolVar(&list, "list", false, "List all payloads")
	flag.BoolVar(&silent, "silent", false, "Silent module")
	flag.Parse()
}

func main() {
	if list {
		detectors.ListAll()
		return
	}
	options := schema.Options{
		"Username": username,
		"CN_Uname": cn_uname,
		"IP":       ip,
		"QQ":       qq,
		"WB_Uid":   wb,
		"Phone":    phone,
		"Domain":   domain,
	}
	options = options.CheckMetadata()
	if len(options) == 0 {
		flag.PrintDefaults()
		return
	}
	if !silent {
		logger.Debug = true
		for _, d := range detectors.Detectors {
			d.Run(options)
		}
	} else {
		for _, d := range detectors.Detectors {
			flag, msg := d.Run(options)
			if flag {
				fmt.Println(msg)
			}
		}
	}
}
