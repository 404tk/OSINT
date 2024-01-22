package structs

import "reflect"

type ScanArgs struct {
	UName  string // 英文ID
	CName  string // 中文ID
	IP     string // IP地址
	Domain string // 域名
	QQ     string // QQ号码
}

func (s *ScanArgs) IsEmpty() bool {
	return reflect.DeepEqual(s, &ScanArgs{})
}
