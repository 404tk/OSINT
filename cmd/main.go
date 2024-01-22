package main

import (
	"flag"
	"fmt"
	"osint/pkg/detectors"
	"osint/pkg/structs"
	"osint/utils"
	"osint/utils/logger"
)

var (
	list, silent bool
	args         = structs.ScanArgs{}
)

func init() {
	flag.StringVar(&args.UName, "u", "", "英文ID")
	flag.StringVar(&args.CName, "cu", "", "中文ID")
	flag.StringVar(&args.IP, "ip", "", "IP地址")
	flag.StringVar(&args.Domain, "d", "", "域名")
	flag.StringVar(&args.QQ, "qq", "", "QQ号码")
	flag.StringVar(&utils.GH_Token, "gh", "", "GitHub Token")
	flag.StringVar(&utils.TB_APIKey, "tb", "", "微步APIKey")
	flag.StringVar(&utils.VT_APIKey, "vt", "", "VirusTotal APIKey")
	flag.BoolVar(&list, "list", false, "List all payloads")
	flag.BoolVar(&silent, "silent", false, "Silent module")
	flag.Parse()
}

func main() {
	if list {
		detectors.ListAll()
		return
	}
	if args.IsEmpty() {
		flag.PrintDefaults()
		return
	}
	if !silent {
		logger.Debug = true
		for _, d := range detectors.Detectors {
			d.Run(args)
		}
	} else {
		for _, d := range detectors.Detectors {
			flag, msg := d.Run(args)
			if flag {
				fmt.Println(msg)
			}
		}
	}
}
