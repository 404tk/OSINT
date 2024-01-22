package detectors

import (
	"osint/pkg/structs"
	"osint/utils/logger"

	"github.com/404tk/table"
)

type Detector interface {
	Run(structs.ScanArgs) (bool, string)
	Desc() string
}

var Detectors = make(map[string]Detector)

func register(name string, d Detector) {
	if _, ok := Detectors[name]; ok {
		logger.Error("重复注册：", name)
	}
	Detectors[name] = d
}

type Payload struct {
	Id   int
	Name string
	Desc string
}

func ListAll() {
	list := []Payload{}
	index := 0
	for name, d := range Detectors {
		index += 1
		list = append(list, Payload{
			Id:   index,
			Name: name,
			Desc: d.Desc(),
		})
	}
	table.Output(list)
}
